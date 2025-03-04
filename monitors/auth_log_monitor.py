import re
import os
import time
import subprocess
from typing import Dict, Any
from .base_monitor import BaseMonitor

class AuthLogMonitor(BaseMonitor):
    """Monitor authentication logs for security events."""
    
    def __init__(self, logger):
        super().__init__(logger)
        self.auth_log_paths = [
            "/var/log/auth.log",       # Debian/Ubuntu
            "/var/log/secure",         # RedHat/CentOS
            "/var/log/messages"        # Fallback
        ]
    
    def run(self):
        """Monitor authentication logs for security events."""
        # Find the appropriate auth log file
        auth_log = None
        for path in self.auth_log_paths:
            if os.path.exists(path) and os.access(path, os.R_OK):
                auth_log = path
                break
        
        if not auth_log:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": "No readable authentication log file found"}, 
                level="WARNING"
            )
            # Try to use journalctl as a fallback
            if self.has_journalctl():
                self.monitor_auth_with_journalctl()
            return
        
        # Pattern matching for common auth events
        patterns = {
            "USER_LOGIN_FAILURE": re.compile(r"(?:Failed password|authentication failure|failed login)"),
            "USER_LOGIN_SUCCESS": re.compile(r"(?:Accepted password|session opened)"),
            "SUDO_COMMAND": re.compile(r"sudo:"),
            "USER_CREATED": re.compile(r"(?:new user|new account|useradd)"),
            "USER_DELETED": re.compile(r"(?:delete user|userdel)"),
            "ACCOUNT_LOCKED": re.compile(r"(?:account locked|too many authentication failures)"),
        }
        
        # Start monitoring the log file
        try:
            with open(auth_log, "r") as f:
                # Move to the end of the file
                f.seek(0, os.SEEK_END)
                
                while self.running:
                    line = f.readline()
                    if line:
                        # Check for security events
                        for event_type, pattern in patterns.items():
                            if pattern.search(line):
                                details = {
                                    "message": line.strip(), 
                                    "source": auth_log
                                }
                                
                                # Try to extract username
                                user_match = re.search(r"user[=:\s]+(\w+)", line, re.IGNORECASE)
                                if user_match:
                                    details["username"] = user_match.group(1)
                                
                                level = "WARNING" if event_type in ["USER_LOGIN_FAILURE", "ACCOUNT_LOCKED"] else "INFO"
                                self.logger.log_event(event_type, details, level=level)
                    else:
                        time.sleep(0.1)
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring auth log: {str(e)}"}, 
                level="ERROR"
            )
    
    def has_journalctl(self):
        """Check if journalctl is available."""
        try:
            subprocess.run(["which", "journalctl"], 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE)
            return True
        except:
            return False
    
    def monitor_auth_with_journalctl(self):
        """Use journalctl to monitor auth events as fallback."""
        try:
            # Set up the journalctl process to follow auth events
            process = subprocess.Popen(
                ["journalctl", "-f", "-t", "sshd", "-t", "sudo", "-t", "auth"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Pattern matching for common auth events
            patterns = {
                "USER_LOGIN_FAILURE": re.compile(r"(?:Failed password|authentication failure|failed login)"),
                "USER_LOGIN_SUCCESS": re.compile(r"(?:Accepted password|session opened)"),
                "SUDO_COMMAND": re.compile(r"sudo:"),
                "USER_CREATED": re.compile(r"(?:new user|new account|useradd)"),
                "USER_DELETED": re.compile(r"(?:delete user|userdel)"),
                "ACCOUNT_LOCKED": re.compile(r"(?:account locked|too many authentication failures)"),
            }
            
            # Process output
            while self.running:
                line = process.stdout.readline()
                if not line:
                    break
                
                # Check for security events
                for event_type, pattern in patterns.items():
                    if pattern.search(line):
                        details = {
                            "message": line.strip(), 
                            "source": "journalctl"
                        }
                        
                        # Try to extract username
                        user_match = re.search(r"user[=:\s]+(\w+)", line, re.IGNORECASE)
                        if user_match:
                            details["username"] = user_match.group(1)
                        
                        level = "WARNING" if event_type in ["USER_LOGIN_FAILURE", "ACCOUNT_LOCKED"] else "INFO"
                        self.logger.log_event(event_type, details, level=level)
            
            # Clean up
            process.terminate()
            
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring with journalctl: {str(e)}"}, 
                level="ERROR"
            )