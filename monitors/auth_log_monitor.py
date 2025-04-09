# File: auth_log_monitor.py
# Security Event Logger - Authentication Log Monitor Module
# Monitors authentication logs for login attempts and sudo commands
import os
import re
import time
from .base_monitor import BaseMonitor

class AuthLogMonitor(BaseMonitor):
    """Monitor authentication logs for security events."""
    
    def __init__(self, logger):
        super().__init__(logger)
        self.auth_log_paths = [
            "/var/log/auth.log",
            "/var/log/secure"
        ]
        self.current_position = {}
    
    def run(self):
        """Monitor auth logs for security events."""
        # Find the auth log file
        auth_log = None
        for path in self.auth_log_paths:
            if os.path.exists(path):
                auth_log = path
                break
        
        if not auth_log:
            self.logger.log_event(
                "MONITOR_WARNING", 
                {"message": "Authentication log file not found"}, 
                level="WARNING"
            )
            return
        
        try:
            # Open the log file and seek to the end
            with open(auth_log, 'r') as f:
                f.seek(0, 2)  # Seek to the end
                self.current_position[auth_log] = f.tell()
            
            # Monitor for new lines
            while self.running:
                if os.path.exists(auth_log):
                    with open(auth_log, 'r') as f:
                        f.seek(self.current_position[auth_log])
                        for line in f:
                            self.process_auth_line(line)
                        self.current_position[auth_log] = f.tell()
                
                time.sleep(0.1)  # Short sleep to reduce CPU usage
                
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring auth log: {str(e)}"}, 
                level="ERROR"
            )
    
    def process_auth_line(self, line):
        """Process a line from the auth log and log security events."""
        # Check for successful login
        if re.search(r'Accepted (password|publickey) for (\S+)', line):
            match = re.search(r'Accepted (password|publickey) for (\S+) from (\S+)', line)
            if match:
                auth_type, username, source = match.groups()
                self.logger.log_event(
                    "USER_LOGIN_SUCCESS", 
                    {
                        "username": username,
                        "source": source,
                        "auth_type": auth_type,
                        "message": f"User {username} logged in successfully from {source}"
                    }
                )
        
        # Check for failed login
        elif re.search(r'Failed password for (\S+)', line):
            match = re.search(r'Failed password for (\S+) from (\S+)', line)
            if match:
                username, source = match.groups()
                self.logger.log_event(
                    "USER_LOGIN_FAILURE", 
                    {
                        "username": username,
                        "source": "auth.log",  # Set specific source here
                        "message": f"Failed login attempt for user {username} from {source}"
                    },
                    level="WARNING"
                )
        
        # Check for invalid user
        elif re.search(r'Invalid user (\S+)', line):
            match = re.search(r'Invalid user (\S+) from (\S+)', line)
            if match:
                username, source = match.groups()
                self.logger.log_event(
                    "USER_LOGIN_FAILURE", 
                    {
                        "username": username,
                        "source": source,
                        "message": f"Login attempt with invalid user {username} from {source}"
                    },
                    level="WARNING"
                )
        
        # Check for sudo command
        elif re.search(r'sudo: (\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(\S+)', line):
            match = re.search(r'sudo: (\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)$', line)
            if match:
                username, tty, pwd, target_user, command = match.groups()
                self.logger.log_event(
                    "SUDO_COMMAND", 
                    {
                        "username": username,
                        "target_user": target_user,
                        "command": command,
                        "pwd": pwd,
                        "message": f"User {username} executed sudo as {target_user}: {command}"
                    },
                    level="WARNING"
                )