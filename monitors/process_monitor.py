import os
import time
import psutil
import threading
import subprocess  # Add this import for sudo_watcher
from datetime import datetime
from .base_monitor import BaseMonitor

class ProcessMonitor(BaseMonitor):
    """Monitor processes for suspicious activity."""
    
    def __init__(self, logger):
        super().__init__(logger)
        self.process_cache = {}
        self.last_check_time = datetime.now()
        self.suspicious_commands = [
            "wget", "curl", "nc", "netcat", "nmap", "tcpdump", "wireshark",
            "ssh-keygen", "ssh-copy-id", "dd", "shred", "rm -rf", "chmod 777",
            "pacman", "apt", "apt-get", "yum", "dnf", "zypper", 
            "sudo", "su", "visudo", "chown", "chmod", "systemctl"
        ]
        
        # Add a specific sudo watcher thread
        self.sudo_watcher_active = False
    
    def run(self):
        """Monitor processes for suspicious activity."""
        try:
            # Start with empty cache
            self.process_cache = {}
            
            # Brief pause to let system stabilize
            time.sleep(0.5)
            
            # Start sudo watcher in separate thread
            self.start_sudo_watcher()
            
            # Get initial process snapshot
            self.process_cache = self.get_processes()
            self.last_check_time = datetime.now()
            
            # Monitor for changes
            while self.running:
                current_time = datetime.now()
                # Get current processes
                current_processes = self.get_processes()
                
                # Check for new processes - critical for detection
                for pid, proc_info in current_processes.items():
                    # Look for completely new processes not in our cache
                    if pid not in self.process_cache:
                        self.log_new_process(proc_info)
                
                # Check for terminated processes (less important)
                for pid, proc_info in list(self.process_cache.items()):
                    if pid not in current_processes:
                        self.log_terminated_process(proc_info)
                
                # Save current timestamp
                self.last_check_time = current_time
                
                # Update cache
                self.process_cache = current_processes
                
                # Brief sleep between checks - shorter interval for better detection
                time.sleep(0.1)  # Check 10 times per second
                
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring processes: {str(e)}"}, 
                level="ERROR"
            )
        finally:
            # Stop sudo watcher when monitor stops
            self.sudo_watcher_active = False
    
    def start_sudo_watcher(self):
        """Start a specialized thread to watch for sudo usage."""
        self.sudo_watcher_active = True
        sudo_thread = threading.Thread(target=self.sudo_watcher, daemon=True)
        sudo_thread.start()
    
    def sudo_watcher(self):
        """Monitor specifically for sudo commands using journalctl."""
        try:
            # Start a journalctl process to watch for sudo entries in real-time
            process = subprocess.Popen(
                ["journalctl", "-f", "_COMM=sudo"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Process each line as it comes in
            while self.sudo_watcher_active:
                line = process.stdout.readline()
                if not line:
                    break
                
                # Parse the line to extract sudo command details
                sudo_user = "unknown"
                sudo_command = "unknown"
                
                # Extract username and command if possible
                if "USER=" in line:
                    sudo_user = line.split("USER=")[1].split(" ")[0]
                
                if "COMMAND=" in line:
                    sudo_command = line.split("COMMAND=")[1].strip()
                
                # Create detailed message
                message = f"Sudo command executed by {sudo_user}: {sudo_command}"
                
                # Log the event with detailed information
                details = {
                    "message": message,
                    "username": sudo_user,
                    "cmdline": sudo_command,
                    "source": "sudo",
                }
                
                # Log as a high-priority security event
                self.logger.log_event("SUDO_COMMAND", details, level="WARNING")
                
            # Clean up
            process.terminate()
            
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error in sudo watcher: {str(e)}"}, 
                level="ERROR"
            )
    
    def get_processes(self):
        """Get current processes with improved detail capture."""
        processes = {}
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
                try:
                    info = proc.info
                    
                    # Skip processes with no command line (kernel threads)
                    if not info['cmdline']:
                        continue
                        
                    # Join cmdline with spaces to form a command string
                    cmdline = " ".join(info['cmdline']) if info['cmdline'] else ""
                    
                    # Get parent process information
                    ppid = None
                    parent_name = ""
                    try:
                        parent = psutil.Process(proc.ppid())
                        ppid = parent.pid
                        parent_name = parent.name()
                    except:
                        pass
                    
                    processes[info['pid']] = {
                        "pid": info['pid'],
                        "name": info['name'],
                        "username": info['username'],
                        "cmdline": cmdline,
                        "create_time": info['create_time'],
                        "ppid": ppid,
                        "parent_name": parent_name
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Skip processes that disappear or can't be accessed
                    continue
        except Exception as e:
            print(f"Error getting processes: {e}")
        
        return processes
    
    def is_suspicious_process(self, proc_info):
        """Check if a process is suspicious with improved detection."""
        is_suspicious = False
        
        # Get the full command line and make lowercase for matching
        cmdline = proc_info.get("cmdline", "").lower()
        
        # Check if this is a privileged process (root user)
        is_privileged = proc_info.get("username") == "root"
        
        # Check for sudo or su in parent process name
        is_sudo_child = proc_info.get("parent_name") in ["sudo", "su"]
        
        # Check command line for suspicious commands
        for cmd in self.suspicious_commands:
            if cmd in cmdline.split():
                is_suspicious = True
                break
        
        # Always flag sudo/su commands as suspicious
        if cmdline.startswith("sudo ") or cmdline.startswith("su "):
            is_suspicious = True
        
        # Flag privileged command execution
        if is_privileged or is_sudo_child:
            is_suspicious = True
        
        return is_suspicious
    
    def log_new_process(self, proc_info):
        """Log a new process with enhanced details."""
        is_suspicious = self.is_suspicious_process(proc_info)
        
        # Create detailed message
        message = f"New process: {proc_info['name']} (PID: {proc_info['pid']}, User: {proc_info['username']})"
        if proc_info.get("cmdline"):
            message += f", Command: {proc_info['cmdline']}"
        if proc_info.get("parent_name"):
            message += f", Parent: {proc_info['parent_name']} (PID: {proc_info.get('ppid', 'unknown')})"
        
        details = {
            "message": message,
            "pid": proc_info["pid"],
            "name": proc_info["name"],
            "username": proc_info["username"],
            "cmdline": proc_info["cmdline"],
            "exe": proc_info.get("exe", ""),
            "cwd": proc_info.get("cwd", ""),
            "ppid": proc_info.get("ppid"),
            "parent_name": proc_info.get("parent_name")
        }
        
        # Determine event type and level
        event_type = "SUSPICIOUS_COMMAND" if is_suspicious else "PROCESS_CREATED"
        level = "WARNING" if is_suspicious else "INFO"
        
        # Log the event
        self.logger.log_event(event_type, details, level=level)
    
    def log_terminated_process(self, proc_info):
        """Log a terminated process."""
        details = {
            "message": f"Process terminated: {proc_info['name']} (PID: {proc_info['pid']}, User: {proc_info['username']})",
            "pid": proc_info["pid"],
            "name": proc_info["name"],
            "username": proc_info["username"],
            "cmdline": proc_info["cmdline"]
        }
        
        # Log the event
        self.logger.log_event("PROCESS_TERMINATED", details)