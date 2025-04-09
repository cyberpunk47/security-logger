# File: syslog_monitor.py
# Security Event Logger - System Log Monitor Module
# Monitors syslog for security events
import os
import re
import time
from .base_monitor import BaseMonitor

class SyslogMonitor(BaseMonitor):
    """Monitor system logs for security events."""
    
    def __init__(self, logger):
        super().__init__(logger)
        self.syslog_paths = [
            "/var/log/syslog",
            "/var/log/messages"
        ]
        self.current_position = {}
    
    def run(self):
        """Monitor syslog for security events."""
        # Find the syslog file
        syslog = None
        for path in self.syslog_paths:
            if os.path.exists(path):
                syslog = path
                break
        
        if not syslog:
            self.logger.log_event(
                "MONITOR_WARNING", 
                {"message": "Syslog file not found"}, 
                level="WARNING"
            )
            return
        
        try:
            # Open the log file and seek to the end
            with open(syslog, 'r') as f:
                f.seek(0, 2)  # Seek to the end
                self.current_position[syslog] = f.tell()
            
            # Monitor for new lines
            while self.running:
                if os.path.exists(syslog):
                    with open(syslog, 'r') as f:
                        f.seek(self.current_position[syslog])
                        for line in f:
                            self.process_syslog_line(line)
                        self.current_position[syslog] = f.tell()
                
                time.sleep(0.1)  # Short sleep to reduce CPU usage
                
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring syslog: {str(e)}"}, 
                level="ERROR"
            )
    
    def process_syslog_line(self, line):
        """Process a line from syslog and log security events."""
        # Check for firewall events (iptables)
        if re.search(r'iptables|firewall|UFW', line, re.IGNORECASE):
            self.logger.log_event(
                "FIREWALL_CHANGE", 
                {
                    "message": f"Firewall event: {line.strip()}",
                    "raw_log": line.strip()
                }
            )
        
        # Check for service starts/stops
        elif re.search(r'systemd\[\d+\]: Started|systemd\[\d+\]: Stopped', line):
            match = re.search(r'systemd\[\d+\]: (Started|Stopped) (.+?)\.', line)
            if match:
                action, service = match.groups()
                event_type = "SERVICE_START" if action == "Started" else "SERVICE_STOP"
                self.logger.log_event(
                    event_type, 
                    {
                        "service": service,
                        "message": f"{action} service: {service}",
                        "raw_log": line.strip()
                    }
                )
        
        # Check for package management
        elif re.search(r'apt|dpkg|yum|dnf|pacman', line, re.IGNORECASE):
            if re.search(r'install|upgrade|remove', line, re.IGNORECASE):
                self.logger.log_event(
                    "SYSTEM_CHANGE", 
                    {
                        "message": f"Package management: {line.strip()}",
                        "raw_log": line.strip()
                    }
                )