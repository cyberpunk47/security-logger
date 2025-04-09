# File: journald_monitor.py
# Security Event Logger - Systemd Journal Monitor Module
# Monitors systemd journal for security events
import re
import time
from .base_monitor import BaseMonitor

# Make systemd import optional
try:
    from systemd import journal
    HAS_SYSTEMD = True
except ImportError:
    HAS_SYSTEMD = False

class JournaldMonitor(BaseMonitor):
    """Monitor systemd journal for security events."""
    
    def __init__(self, logger):
        super().__init__(logger)
    
    def run(self):
        """Monitor journald for security events."""
        if not HAS_SYSTEMD:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": "Systemd journal support not available"}, 
                level="WARNING"
            )
            return
        
        try:
            # Create a journal reader
            j = journal.Reader()
            j.this_boot()
            j.log_level(journal.LOG_INFO)
            
            # Add filters for security-related entries
            j.add_match(_SYSTEMD_UNIT="sshd.service")
            j.add_match(_SYSTEMD_UNIT="sudo.service")
            j.add_match(_SYSTEMD_UNIT="systemd-logind.service")
            j.add_match(_SYSTEMD_UNIT="polkit.service")
            j.add_match(_SYSTEMD_UNIT="firewalld.service")
            
            # Seek to the end
            j.seek_tail()
            j.get_previous()
            
            # Monitor for new entries
            while self.running:
                for entry in j:
                    # Process the entry
                    self.process_journal_entry(entry)
                
                if j.wait(0.1) == journal.NOP:
                    time.sleep(0.1)
                    
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring journald: {str(e)}"}, 
                level="ERROR"
            )
    
    def process_journal_entry(self, entry):
        """Process a journal entry and log security events."""
        try:
            # Extract useful fields
            message = entry.get("MESSAGE", "")
            unit = entry.get("_SYSTEMD_UNIT", "")
            priority = entry.get("PRIORITY", "6")  # Default to info
            
            # Determine event type based on unit and message content
            event_type = "INFORMATION"
            
            if "sshd" in unit:
                if "Failed password" in message or "authentication failure" in message:
                    event_type = "USER_LOGIN_FAILURE"
                elif "Accepted password" in message or "session opened" in message:
                    event_type = "USER_LOGIN_SUCCESS"
            elif "sudo" in unit or "sudo:" in message:
                event_type = "SUDO_COMMAND"
            elif "firewalld" in unit or ("iptables" in message or "firewall" in message.lower()):
                event_type = "FIREWALL_CHANGE"
            elif "polkit" in unit and "auth" in message.lower():
                event_type = "PRIVILEGE_ESCALATION"
            elif "systemd-logind" in unit and "session" in message.lower():
                if "New session" in message:
                    event_type = "USER_LOGIN_SUCCESS"
                elif "Removed session" in message:
                    event_type = "USER_LOGOUT"
            
            # Determine level based on journal priority
            level = "INFO"
            if priority in ["3", "2", "1", "0"]:  # err, crit, alert, emerg
                level = "ERROR"
            elif priority == "4":  # warning
                level = "WARNING"
            
            # Extract username if present
            username = None
            user_match = re.search(r"user[=:\s]+(\w+)", message, re.IGNORECASE)
            if user_match:
                username = user_match.group(1)
            
            # Create details
            details = {
                "message": message,
                "source": unit,
                "priority": priority
            }
            
            if username:
                details["username"] = username
            
            # Log the event
            self.logger.log_event(event_type, details, level=level)
            
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error processing journal entry: {str(e)}"}, 
                level="ERROR"
            )