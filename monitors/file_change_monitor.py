import os
import time
import pwd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .base_monitor import BaseMonitor

class FileChangeMonitor(BaseMonitor):
    """Monitor file system changes in critical directories."""
    
    def __init__(self, logger, watched_dirs=None):
        super().__init__(logger)
        self.watched_dirs = watched_dirs or ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        self.observer = None
    
    def run(self):
        """Monitor file system changes."""
        try:
            # Define event handler
            class EventHandler(FileSystemEventHandler):
                def __init__(self, monitor):
                    self.monitor = monitor
                
                def on_created(self, event):
                    self.log_event(event, "FILE_CREATED")
                
                def on_deleted(self, event):
                    self.log_event(event, "FILE_DELETED")
                
                def on_modified(self, event):
                    self.log_event(event, "FILE_MODIFIED")
                
                def on_moved(self, event):
                    self.log_event(event, "FILE_MOVED")
                
                def log_event(self, event, event_type):
                    # Get file owner
                    username = "UNKNOWN"
                    try:
                        stat_info = os.stat(event.src_path)
                        username = pwd.getpwuid(stat_info.st_uid).pw_name
                    except:
                        pass
                    
                    # Create details
                    details = {
                        "message": f"File change detected: {event.src_path}",
                        "path": event.src_path,
                        "username": username,
                        "event_type": event_type
                    }
                    
                    # Determine if this is a sensitive file
                    is_sensitive = event.src_path in [
                        "/etc/passwd", "/etc/shadow", "/etc/sudoers", 
                        "/etc/ssh/sshd_config", "/etc/pam.d/common-auth"
                    ]
                    
                    # Log the event
                    level = "WARNING" if is_sensitive else "INFO"
                    self.monitor.logger.log_event(event_type, details, level=level)
            
            # Set up the observer
            self.observer = Observer()
            handler = EventHandler(self)
            
            # Add watches for all directories
            for directory in self.watched_dirs:
                if os.path.exists(directory) and os.access(directory, os.R_OK):
                    self.observer.schedule(handler, directory, recursive=True)
                    self.logger.log_event(
                        "MONITOR_INFO", 
                        {"message": f"Watching directory: {directory}"}, 
                        level="INFO"
                    )
                else:
                    self.logger.log_event(
                        "MONITOR_WARNING", 
                        {"message": f"Cannot watch directory (not found or no access): {directory}"}, 
                        level="WARNING"
                    )
            
            # Start the observer
            self.observer.start()
            
            # Keep the thread alive
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring file changes: {str(e)}"}, 
                level="ERROR"
            )
        finally:
            # Clean up
            if self.observer is not None:
                self.observer.stop()
                self.observer.join()
    
    def stop(self):
        """Stop the file change monitor."""
        super().stop()
        if self.observer is not None:
            self.observer.stop()
            self.observer.join()