# File: __init__.py
# Security Event Logger - Monitors Package Initialization
# Import all monitor classes to make them available when importing the monitors package
from .base_monitor import BaseMonitor

# File: auditd_monitor.py
# Security Event Logger - Auditd Monitor Module
# Monitors Linux audit daemon logs for security events
import subprocess
import time
import pwd
from typing import Dict
from .base_monitor import BaseMonitor

class AuditdMonitor(BaseMonitor):
    """Monitor Linux audit daemon logs."""
    
    def __init__(self, logger):
        super().__init__(logger)
    
    def run(self):
        """Monitor auditd logs for security events."""
        if not self.is_auditd_available():
            self.logger.log_event(
                "MONITOR_WARNING", 
                {"message": "Auditd not available or running"}, 
                level="WARNING"
            )
            return
        
        try:
            # We'll use ausearch to get recent audit events
            while self.running:
                # Get events from the last minute
                process = subprocess.Popen(
                    ["ausearch", "-ts", "recent"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate()
                
                if stderr:
                    self.logger.log_event(
                        "MONITOR_ERROR",
                        {"message": f"Auditd error: {stderr}"}, 
                        level="ERROR"
                    )
                
                if stdout:
                    # Process audit events
                    self.process_audit_events(stdout)
                
                time.sleep(60)  # Check once per minute
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring auditd: {str(e)}"}, 
                level="ERROR"
            )
    
    def is_auditd_available(self) -> bool:
        """Check if auditd is available and running."""
        try:
            # Check if ausearch is available
            process = subprocess.run(
                ["which", "ausearch"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if process.returncode != 0:
                return False
            
            # Check if auditd service is running
            process = subprocess.run(
                ["systemctl", "is-active", "auditd"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return process.stdout.strip() == "active"
        except Exception:
            return False
    
    def process_audit_events(self, audit_output: str):
        """Process and log audit events."""
        # Parse audit records
        current_event = {}
        
        for line in audit_output.splitlines():
            if line.startswith("----"):
                # New event boundary
                if current_event:
                    self.log_audit_event(current_event)
                    current_event = {}
                continue
            
            # Parse key=value pairs
            for part in line.split():
                if "=" in part:
                    key, value = part.split("=", 1)
                    current_event[key] = value
        
        # Don't forget the last event
        if current_event:
            self.log_audit_event(current_event)
    
    def log_audit_event(self, event: Dict[str, str]):
        """Log an audit event."""
        # Determine the event type
        event_type = event.get("type", "UNKNOWN")
        
        # Map audit events to Windows-style event types
        event_mapping = {
            "USER_AUTH": "USER_LOGIN_SUCCESS",
            "USER_LOGIN": "USER_LOGIN_SUCCESS",
            "USER_CMD": "PROCESS_CREATED",
            "USER_ACCT": "USER_CREATED",
            "USER_ROLE_CHANGE": "SPECIAL_PRIVILEGE",
            "CRED_ACQ": "SPECIAL_PRIVILEGE",
            "CRED_DISP": "USER_LOGOUT",
            "SYSCALL": "PROCESS_CREATED",
            "PATH": "FILE_ACCESS",
            "CONFIG_CHANGE": "FIREWALL_CHANGE",
            "PRIV_ESCALATION": "PRIVILEGE_ESCALATION"
        }
        
        # Map to Windows-style event
        win_event_type = event_mapping.get(event_type, "SECURITY_AUDIT")
        
        # Create details
        details = {
            "message": f"Audit event: {event_type}",
            "source": "auditd",
            "raw_event": event
        }
        
        # Extract username if available
        if "uid" in event:
            try:
                user = pwd.getpwuid(int(event["uid"]))
                details["username"] = user.pw_name
            except:
                details["username"] = event.get("uid", "UNKNOWN")
        
        # Determine severity level
        level = "INFO"
        if win_event_type in ["USER_LOGIN_FAILURE", "PRIVILEGE_ESCALATION", "SUSPICIOUS_COMMAND"]:
            level = "WARNING"
        
        # Log the event
        self.logger.log_event(win_event_type, details, level=level)