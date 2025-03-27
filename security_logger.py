import os
import sys
import time
import json
import signal
import argparse
import datetime
import subprocess
import logging
import logging.handlers
from pathlib import Path
import threading
import queue
import re
import socket
import pwd
import grp
import uuid
import configparser
import sqlite3
from typing import Dict, List, Any, Optional, Union
import tempfile
import getpass  # Add missing import

# Import monitor classes from the monitors package
from monitors import (
    AuthLogMonitor,
    AuditdMonitor,
    SyslogMonitor,
    JournaldMonitor,
    FileChangeMonitor,
    NetworkMonitor,
    ProcessMonitor,
)

# Import EventDatabase
from event_database import EventDatabase  # Add this import

# Add this import at the top
from PyQt5.QtCore import QObject, pyqtSignal

# Function to check and install required dependencies
def check_and_install_dependencies():
    required_packages = {
        "psutil": "psutil",
        "watchdog": "watchdog",
        "systemd-python": "systemd",
        "PyQt5": "PyQt5",
        "matplotlib": "matplotlib",
        "pandas": "pandas",
        "python-dateutil": "dateutil", 
    }
    
    # Check which packages need to be installed
    missing_packages = []
    for package_name, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(package_name)
    
    # Install missing packages if any
    if (missing_packages):
        print(f"Installing missing dependencies: {', '.join(missing_packages)}")
        try:
            # Try using pip in user mode first (no admin required)
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--user"] + missing_packages,
                check=True
            )
        except subprocess.CalledProcessError:
            # If that fails, try creating a virtual environment
            print("Could not install with pip. Creating a virtual environment...")
            venv_dir = os.path.join(tempfile.gettempdir(), "seclog_venv")
            try:
                subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)
                venv_python = os.path.join(venv_dir, "bin", "python")
                subprocess.run(
                    [venv_python, "-m", "pip", "install"] + missing_packages,
                    check=True
                )
                print(f"Created virtual environment at {venv_dir}")
                print(f"Please run this script with: {venv_python} {sys.argv[0]}")
                sys.exit(0)
            except subprocess.CalledProcessError:
                print("Failed to create virtual environment. Please install the following packages manually:")
                for package in missing_packages:
                    print(f"  - {package}")
                sys.exit(1)

# Try to import after installing
try:
    check_and_install_dependencies()
    import psutil
    from watchdog.observers import Observer  # Import watchdog instead of pyinotify
    
    # Try to import systemd, but make it optional
    try:
        from systemd import journal
        HAS_SYSTEMD = True
    except ImportError:
        HAS_SYSTEMD = False
except Exception as e:
    print(f"Error setting up dependencies: {e}")
    sys.exit(1)

class SecurityEventLogger(QObject):
    """Main class for Windows-style security event logging on Linux."""
    
    # Add a PyQt signal for new events
    new_event = pyqtSignal(dict)
    
    # Windows Event Log-inspired event types
    EVENT_TYPES = {
        "INFORMATION": 1,  # Normal operation
        "WARNING": 2,      # Potential issue
        "ERROR": 3,        # Error condition
        "SECURITY_AUDIT": 4,  # Security audit event
        "SECURITY_ALERT": 5   # Security alert event
    }
    
    # Windows-style event IDs for security events
    EVENT_IDS = {
        # Authentication events (4600-4799 range in Windows)
        "USER_LOGIN_SUCCESS": "4624",
        "USER_LOGIN_FAILURE": "4625",
        "USER_LOGOUT": "4634",
        "ACCOUNT_LOCKED": "4740",
        
        # Account management events (4800-4899 range)
        "USER_CREATED": "4720",
        "USER_DELETED": "4726",
        "USER_ENABLED": "4722",
        "USER_DISABLED": "4725",
        "PASSWORD_CHANGED": "4724",
        
        # System events (1000-1999 range)
        "SYSTEM_START": "1074",
        "SERVICE_START": "7035",
        "SERVICE_STOP": "7036",
        
        # Object access (4656-4699 range)
        "FILE_ACCESS": "4656",
        "FILE_CREATED": "4658",
        "FILE_DELETED": "4660",
        
        # Process tracking (4688-4699 range)
        "PROCESS_CREATED": "4688",
        "PROCESS_TERMINATED": "4689",
        
        # Network events (5140-5159 range)
        "NETWORK_CONNECTION": "5156",
        "FIREWALL_CHANGE": "4950",
        
        # Privilege use (4672-4699 range)
        "SPECIAL_PRIVILEGE": "4672",
        "PRIVILEGE_ESCALATION": "4673",
        
        # Custom events for Linux specifics
        "FILE_PERMISSION_CHANGE": "9001",
        "SUDO_COMMAND": "9002",
        "SUSPICIOUS_COMMAND": "9003"
    }
    
    def __init__(self, config_file=None, gui_mode=False):
        """Initialize the security event logger with configuration."""
        # Initialize QObject first
        super(SecurityEventLogger, self).__init__()
        
        # Set GUI mode
        self.gui_mode = gui_mode
        
        self.config = self.load_config(config_file)
        
        # Set up database in home directory by default
        db_path = self.config.get('database', {}).get('path', os.path.expanduser('~/.local/share/securityevents.db'))
        self.ensure_directory_exists(os.path.dirname(db_path))
        self.db = EventDatabase(db_path)
        
        # Set up logging
        self.setup_logging()
        
        # Initialize event queues
        self.event_queue = queue.Queue()
        
        # Initialize monitors
        self.monitors = []
        self.setup_monitors()
        
        # Track running state
        self.running = False
    
    def load_config(self, config_file):
        """Load configuration from file or use defaults."""
        default_config = {
            "general": {
                "log_level": "INFO",
                "hostname": socket.gethostname()
            },
            "database": {
                "path": os.path.expanduser("~/.local/share/securityevents.db")
            },
            "logging": {
                "file": os.path.expanduser("~/.local/share/securityevents.log"),
                "max_size_mb": 10,
                "backup_count": 5
            },
            "monitors": {
                "auth_log": True,
                "audit": HAS_SYSTEMD,
                "syslog": True,
                "journald": HAS_SYSTEMD,
                "file_changes": True,
                "network": True,
                "processes": True
            },
            "watched_dirs": [
                "/etc",
                "/bin",
                "/sbin",
                "/usr/bin",
                "/usr/sbin"
            ],
            "watched_users": [
                "root"
            ],
            "alerts": {
                "sudo_commands": True,
                "failed_logins": True,
                "root_login": True
            }
        }
        
        # If config file is provided, try to load it
        config = default_config
        if config_file and os.path.exists(config_file):
            try:
                parser = configparser.ConfigParser()
                parser.read(config_file)
                
                # Update default config with values from file
                for section in parser.sections():
                    if section not in config:
                        config[section] = {}
                    for key, value in parser.items(section):
                        # Try to convert boolean values
                        if value.lower() in ('true', 'yes', 'on', '1'):
                            config[section][key] = True
                        elif value.lower() in ('false', 'no', 'off', '0'):
                            config[section][key] = False
                        else:
                            config[section][key] = value
            except Exception as e:
                print(f"Error loading config file: {e}")
        
        return config
    
    def ensure_directory_exists(self, directory):
        """Ensure a directory exists, creating it if necessary."""
        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
            except PermissionError:
                # Fall back to user home directory if permission denied
                fallback_dir = os.path.expanduser("~/.local/share/securityevents")
                os.makedirs(fallback_dir, exist_ok=True)
                return fallback_dir
        return directory
    
    def setup_logging(self):
        """Configure the logging system."""
        log_file = self.config.get('logging', {}).get('file')
        log_dir = os.path.dirname(log_file) if log_file else None
        
        if (log_dir):
            log_dir = self.ensure_directory_exists(log_dir)
            log_file = os.path.join(log_dir, os.path.basename(log_file))
        
        self.logger = logging.getLogger("SecurityEventLogger")
        
        # In GUI mode, use a higher level to reduce verbosity
        if self.gui_mode:
            self.logger.setLevel(logging.WARNING)
        else:
            self.logger.setLevel(getattr(logging, self.config.get('general', {}).get('log_level', 'INFO')))
        
        # Clear existing handlers
        self.logger.handlers = []
        
        # Console handler only when not in GUI mode
        if not self.gui_mode:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s'
            ))
            self.logger.addHandler(console_handler)
        
        # File handler with rotation
        if log_file:
            try:
                max_size = self.config.get('logging', {}).get('max_size_mb', 10) * 1024 * 1024
                backup_count = self.config.get('logging', {}).get('backup_count', 5)
                
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file,
                    maxBytes=max_size,
                    backupCount=backup_count
                )
                file_handler.setFormatter(logging.Formatter(
                    '%(asctime)s [%(levelname)s] %(message)s'
                ))
                self.logger.addHandler(file_handler)
            except Exception as e:
                print(f"Could not set up file logging: {e}")
                
    def setup_monitors(self):
        """Set up security monitors according to configuration."""
        # Always enable process monitoring to catch all processes
        self.monitors.append(ProcessMonitor(self))
        
        # Other monitors depend on configuration
        monitors_config = self.config.get('monitors', {})
        
        # Auth log monitor
        if monitors_config.get('auth_log', True):
            self.monitors.append(AuthLogMonitor(self))
        
        # Audit daemon monitor
        if monitors_config.get('audit', False):
            self.monitors.append(AuditdMonitor(self))
        
        # Syslog monitor
        if monitors_config.get('syslog', True):
            self.monitors.append(SyslogMonitor(self))
        
        # Journald monitor (requires systemd)
        if monitors_config.get('journald', True) and HAS_SYSTEMD:
            self.monitors.append(JournaldMonitor(self))
        
        # File change monitor - reduced scope to essential directories
        if monitors_config.get('file_changes', True):
            watched_dirs = self.config.get('watched_dirs', ["/etc"])
            self.monitors.append(FileChangeMonitor(self, watched_dirs))
        
        # Network monitor
        if monitors_config.get('network', True):
            self.monitors.append(NetworkMonitor(self))
    
    def log_event(self, event_type, details=None, level="INFO"):
        """Log a security event with the specified type and details."""
        if details is None:
            details = {}
        
        # Get current timestamp in ISO format
        timestamp = datetime.datetime.now().isoformat()
        
        # Generate a unique event ID
        event_id = str(uuid.uuid4())
        
        # Get hostname
        try:
            hostname = socket.gethostname()
        except:
            hostname = "unknown"
        
        # Get username
        try:
            username = getpass.getuser()
        except:
            username = "unknown"
        
        # Create event object
        event = {
            "timestamp": timestamp,  # Ensure this is a proper ISO timestamp
            "event_id": event_id,
            "type": event_type,
            "level": level,
            "user": username,
            "computer": hostname,
            "source": "SecurityLogger",
            "description": self.get_event_description(event_type, details),
            "details": json.dumps(details) if isinstance(details, dict) else "{}"
        }
        
        # Add to queue for processing
        self.event_queue.put(event)
        
        # Emit signal for new event
        self.new_event.emit(event)
        
        # Also log to Python logger
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(f"{event_type}: {self.get_event_description(event_type, details)}")
        
        return event
    
    def get_event_description(self, event_type, details=None):
        """Generate a human-readable description for an event type."""
        if details is None:
            details = {}
            
        # Generic description templates
        descriptions = {
            "USER_LOGIN_SUCCESS": "User '{username}' logged in successfully from {source}",
            "USER_LOGIN_FAILURE": "Failed login attempt for user '{username}' from {source}",
            "USER_LOGOUT": "User '{username}' logged out",
            "ACCOUNT_LOCKED": "Account '{username}' was locked after failed attempts",
            "USER_CREATED": "New user account '{username}' was created",
            "USER_DELETED": "User account '{username}' was deleted",
            "USER_ENABLED": "User account '{username}' was enabled",
            "USER_DISABLED": "User account '{username}' was disabled",
            "PASSWORD_CHANGED": "Password changed for user '{username}'",
            "SYSTEM_START": "System started or service initiated",
            "SYSTEM_STOP": "System stopped or service terminated",
            "SERVICE_START": "Service '{service}' started",
            "SERVICE_STOP": "Service '{service}' stopped",
            "FILE_ACCESS": "File '{path}' was accessed by '{username}'",
            "FILE_CREATED": "File '{path}' was created by '{username}'",
            "FILE_DELETED": "File '{path}' was deleted by '{username}'",
            "PROCESS_CREATED": "Process '{name}' was created by '{username}'",
            "PROCESS_TERMINATED": "Process '{name}' was terminated",
            "NETWORK_CONNECTION": "Network connection {source_ip}:{source_port} to {dest_ip}:{dest_port}",
            "FIREWALL_CHANGE": "Firewall rule was changed",
            "SPECIAL_PRIVILEGE": "Special privileges used by '{username}'",
            "PRIVILEGE_ESCALATION": "Privilege escalation by '{username}'",
            "FILE_PERMISSION_CHANGE": "Permissions changed on '{path}'",
            "SUDO_COMMAND": "Sudo command executed by '{username}'",
            "SUSPICIOUS_COMMAND": "Suspicious command executed: '{cmdline}'",
            "SECURITY_AUDIT": "Security audit event: {message}",
            "SECURITY_ALERT": "Security alert: {message}",
            "MONITOR_ERROR": "Monitoring error: {message}",
            "MONITOR_WARNING": "Monitoring warning: {message}",
            "INFORMATION": "{message}"
        }
        
        # Get the template for this event type
        template = descriptions.get(event_type, "{message}")
        
        # Extract variables from details
        try:
            # If details is provided as a JSON string, parse it
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except json.JSONDecodeError:
                    details = {"message": details}
            
            # Set default message if none exists
            if "message" not in details:
                details["message"] = f"{event_type} event occurred"
                
            # Format the template with details
            return template.format(**{**details, **{"event_type": event_type}})
        except KeyError as e:
            # If formatting fails due to missing key, return a generic message
            return f"{event_type}: {details.get('message', 'Event occurred')}"
        except Exception as e:
            # If any other error occurs, return a very generic message
            return f"{event_type} event occurred"
    
    def start(self):
        """Start the security event logger in real-time mode."""
        if self.running:
            return
        
        self.running = True
        self.logger.info("Starting Windows-Style Security Event Logger")
        
        # Check if we need to drop privileges
        if os.geteuid() == 0:
            self.logger.info("Running with root privileges")
        else:
            self.logger.warning("Not running as root, some events may not be captured")
        
        # Start all monitors
        for monitor in self.monitors:
            monitor.start()
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)
        
        # Start the event processor
        self.event_processor = threading.Thread(target=self.process_events)
        self.event_processor.daemon = True
        self.event_processor.start()
        
        # Log startup information
        self.log_system_info()
    
    def log_system_info(self):
        """Log basic system information on startup."""
        system_info = {
            "hostname": socket.gethostname(),
            "kernel": os.uname().release,
            "distro": self.get_distro_info(),
            "started_at": datetime.datetime.now().isoformat(),
            "monitored_subsystems": [m.__class__.__name__ for m in self.monitors],
            "username": pwd.getpwuid(os.geteuid()).pw_name
        }
        self.log_event("SYSTEM_START", system_info)
    
    def get_distro_info(self) -> str:
        """Get Linux distribution information."""
        try:
            # Try to read from os-release file (most modern distros)
            os_release = {}
            os_release_path = "/etc/os-release"
            if os.path.exists(os_release_path):
                with open(os_release_path, "r") as f:
                    for line in f:
                        if "=" in line:
                            key, value = line.strip().split("=", 1)
                            os_release[key] = value.strip('"')
                return f"{os_release.get('NAME', 'Unknown')} {os_release.get('VERSION', '')}"
            return "Unknown Linux"
        except Exception as e:
            self.logger.error(f"Error detecting distro: {str(e)}")
            return "Unknown Linux"
    
    def process_events(self):
        """Process events from the queue with improved priority handling."""
        high_priority_event_types = [
            "SUSPICIOUS_COMMAND", "PRIVILEGE_ESCALATION", "USER_LOGIN_FAILURE",
            "SECURITY_ALERT", "SECURITY_AUDIT"
        ]
        
        high_priority_event_ids = [
            "4625",  # Failed login
            "4740",  # Account locked
            "4672",  # Special privileges
            "9002",  # Sudo command
            "9003"   # Suspicious command
        ]
        
        while self.running:
            try:
                # Process up to 10 events at once for better throughput
                for _ in range(10):
                    try:
                        event = self.event_queue.get(timeout=0.1)
                        
                        # Check event priority
                        event_type = event.get('type')
                        event_id = event.get('event_id')
                        
                        is_high_priority = (
                            event_type in high_priority_event_types or
                            event_id in high_priority_event_ids or
                            event.get('source') in ['sudo', 'su']
                        )
                        
                        # Emit signals for all events (GUI needs this)
                        self.new_event.emit(event)
                        
                        # Print warning for high-priority events if not in GUI mode
                        if is_high_priority and not self.gui_mode:
                            self.logger.warning(f"ALERT: High-priority security event: {event.get('description')}")
                        
                        # Store event in database 
                        self.db.add_event(event)
                        
                        self.event_queue.task_done()
                    except queue.Empty:
                        break
                
                # Short sleep to prevent CPU spinning
                time.sleep(0.05)
            except Exception as e:
                self.logger.error(f"Error processing event: {str(e)}")
                time.sleep(0.1)  # Add a small delay on error
    
    def handle_signal(self, signum, frame):
        """Handle termination signals to gracefully shut down."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def stop(self):
        """Stop all monitors and shutdown."""
        if not self.running:
            return
        
        self.running = False
        self.logger.info("Stopping Windows-Style Security Event Logger")
        
        # Stop all monitors
        for monitor in self.monitors:
            monitor.stop()
        
        # Log shutdown
        self.log_event("SYSTEM_STOP", {
            "reason": "user_requested",
            "shutdown_time": datetime.datetime.now().isoformat()
        })
        
        # Exit
        sys.exit(0)

def main():
    """Main entry point for the security event logger."""
    # Set up command-line arguments
    parser = argparse.ArgumentParser(description="Windows-Style Security Event Logger for Linux")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase verbosity")
    parser.add_argument("--list-events", action="store_true", help="List recent events and exit")
    parser.add_argument("--search", help="Search events with SQL WHERE clause")
    parser.add_argument("--daemon", action="store_true", help="Run as a daemon process")
    parser.add_argument("--install-service", action="store_true", help="Install as a systemd service")
    args = parser.parse_args()
    
    # Set up logging level
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Create the security event logger
    logger = SecurityEventLogger(args.config)
    
    # Handle commands
    if args.list_events:
        # List recent events
        events = logger.db.get_recent_events(100)
        print(f"Recent security events ({len(events)}):")
        for event in events:
            print(f"[{event['date']} {event['time']}] ID {event['event_id']} - {event['type']}: {event['description']}")
        return
    
    if args.search:
        # Search events with SQL WHERE clause
        query = f"SELECT * FROM events WHERE {args.search} ORDER BY id DESC LIMIT 100"
        try:
            events = logger.db.search_events(query, ())
            print(f"Search results ({len(events)}):")
            for event in events:
                print(f"[{event['date']} {event['time']}] ID {event['event_id']} - {event['type']}: {event['description']}")
        except Exception as e:
            print(f"Error searching events: {e}")
        return
    
    if args.install_service:
        # Install as a systemd service
        install_systemd_service()
        return
    
    if args.daemon:
        # Run as a daemon
        daemonize()
    
    # Start the logger in real-time mode
    try:
        logger.start()
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Interrupted by user")
    finally:
        logger.stop()

def daemonize():
    """Daemonize the process."""
    try:
        # First fork
        pid = os.fork()
        if pid > 0:
            # Exit the parent process
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Fork #1 failed: {e}\n")
        sys.exit(1)
    
    # Decouple from parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)
    
    try:
        # Second fork
        pid = os.fork()
        if pid > 0:
            # Exit the second parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Fork #2 failed: {e}\n")
        sys.exit(1)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open('/dev/null', 'r') as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open('/dev/null', 'a+') as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
    with open('/dev/null', 'a+') as f:
        os.dup2(f.fileno(), sys.stderr.fileno())
    
    # Write PID file
    pid_file = '/var/run/seclog.pid'
    try:
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
    except Exception as e:
        # Fall back to temp directory
        pid_file = os.path.join(tempfile.gettempdir(), 'seclog.pid')
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))

def install_systemd_service():
    """Install as a systemd service."""
    # Create service file content
    service_content = """[Unit]
Description=Windows-Style Security Event Logger
After=network.target

[Service]
Type=simple
ExecStart={executable} {script} --daemon
Restart=on-failure
RestartSec=5s
User=root

[Install]
WantedBy=multi-user.target
""".format(executable=sys.executable, script=os.path.abspath(sys.argv[0]))
    
    # Write service file
    service_path = "/etc/systemd/system/seclog.service"
    try:
        with open(service_path, 'w') as f:
            f.write(service_content)
    except PermissionError:
        print("Error: Root privileges required to install systemd service.")
        sys.exit(1)
    
    # Enable and start the service
    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "seclog.service"], check=True)
        subprocess.run(["systemctl", "start", "seclog.service"], check=True)
        print("Service installed and started successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to configure systemd service: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()