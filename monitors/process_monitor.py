import os
import time
import psutil
from .base_monitor import BaseMonitor

class ProcessMonitor(BaseMonitor):
    """Monitor processes for suspicious activity."""
    
    def __init__(self, logger):
        super().__init__(logger)
        self.process_cache = {}
        self.suspicious_commands = [
            "wget", "curl", "nc", "netcat", "nmap", "tcpdump", "wireshark",
            "ssh-keygen", "ssh-copy-id", "dd", "shred", "rm -rf", "chmod 777"
        ]
    
    def run(self):
        """Monitor processes for suspicious activity."""
        try:
            # Record initial state
            self.process_cache = self.get_processes()
            
            # Monitor for changes
            while self.running:
                # Get current processes
                current_processes = self.get_processes()
                
                # Check for new processes
                for pid, proc_info in current_processes.items():
                    if pid not in self.process_cache:
                        self.log_new_process(proc_info)
                
                # Check for terminated processes
                for pid, proc_info in self.process_cache.items():
                    if pid not in current_processes:
                        self.log_terminated_process(proc_info)
                
                # Update cache
                self.process_cache = current_processes
                
                # Check every 5 seconds
                time.sleep(5)
                
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring processes: {str(e)}"}, 
                level="ERROR"
            )
    
    def get_processes(self):
        """Get current processes."""
        processes = {}
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
                info = proc.info
                processes[info['pid']] = {
                    "pid": info['pid'],
                    "name": info['name'],
                    "username": info['username'],
                    "cmdline": " ".join(info['cmdline']) if info['cmdline'] else "",
                    "create_time": info['create_time']
                }
        except:
            pass
        
        return processes
    
    def is_suspicious_process(self, proc_info):
        """Check if a process is suspicious."""
        # Check for root processes started by non-root users
        is_suspicious = False
        
        # Check command line for suspicious commands
        cmdline = proc_info.get("cmdline", "").lower()
        for cmd in self.suspicious_commands:
            if cmd in cmdline:
                is_suspicious = True
                break
        
        # Check if it's a user running with elevated privileges
        username = proc_info.get("username", "")
        if username == "root" and os.geteuid() != 0:
            is_suspicious = True
        
        return is_suspicious
    
    def log_new_process(self, proc_info):
        """Log a new process."""
        is_suspicious = self.is_suspicious_process(proc_info)
        
        details = {
            "message": f"New process: {proc_info['name']} (PID: {proc_info['pid']}, User: {proc_info['username']})",
            "pid": proc_info["pid"],
            "name": proc_info["name"],
            "username": proc_info["username"],
            "cmdline": proc_info["cmdline"]
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