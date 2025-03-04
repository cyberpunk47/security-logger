import re
import os
import time
from typing import Dict, Any
from .base_monitor import BaseMonitor

class SyslogMonitor(BaseMonitor):
    """Monitor system logs for security events."""
    
    def __init__(self, logger):
        super().__init__(logger)
        self.syslog_paths = [
            "/var/log/syslog",      # Debian/Ubuntu
            "/var/log/messages",    # RedHat/CentOS
        ]
    
    def run(self):
        """Monitor syslog for security events."""
        # Find an accessible syslog file
        syslog = None
        for path in self.syslog_paths:
            if os.path.exists(path) and os.access(path, os.R_OK):
                syslog = path
                break
        
        if not syslog:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": "No readable syslog file found"}, 
                level="WARNING"
            )
            return
        
        # Pattern matching for common syslog events
        patterns = {
            "SERVICE_START": re.compile(r"(?:Starting|Started|Reached target)"),
            "SERVICE_STOP": re.compile(r"(?:Stopping|Stopped|Stopped target)"),
            "FIREWALL_CHANGE": re.compile(r"(?:iptables|firewalld|ufw)"),
            "SYSTEM_ERROR": re.compile(r"(?:error|failure)"),
            "DISK_ERROR": re.compile(r"(?:I/O error|disk error)"),
            "NETWORK_CHANGE": re.compile(r"(?:interface|Network|link up|link down)"),
            "SECURITY_VIOLATION": re.compile(r"(?:violation|denied|blocked)")
        }
        
        # Start monitoring the log file
        try:
            with open(syslog, "r") as f:
                # Move to the end of the file
                f.seek(0, os.SEEK_END)
                
                while self.running:
                    line = f.readline()
                    if line:
                        # Check for security events
                        for event_type, pattern in patterns.items():
                            if pattern.search(line.lower()):
                                details = {
                                    "message": line.strip(), 
                                    "source": syslog
                                }
                                
                                level = "WARNING" if event_type in ["SYSTEM_ERROR", "DISK_ERROR", "SECURITY_VIOLATION"] else "INFO"
                                self.logger.log_event(event_type, details, level=level)
                    else:
                        time.sleep(0.1)
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring syslog: {str(e)}"}, 
                level="ERROR"
            )