import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .base_monitor import BaseMonitor

class FileChangeEventHandler(FileSystemEventHandler):
    """Handle file system events for security monitoring."""
    
    def __init__(self, logger):
        self.logger = logger
    
    def on_created(self, event):
        """Handle file creation event."""
        if not event.is_directory:
            self.logger.log_event(
                "FILE_CREATED", 
                {
                    "path": event.src_path,
                    "message": f"File created: {event.src_path}"
                }
            )
    
    def on_deleted(self, event):
        """Handle file deletion event."""
        if not event.is_directory:
            self.logger.log_event(
                "FILE_DELETED", 
                {
                    "path": event.src_path,
                    "message": f"File deleted: {event.src_path}"
                }
            )
    
    def on_modified(self, event):
        """Handle file modification event."""
        if not event.is_directory:
            self.logger.log_event(
                "FILE_ACCESS", 
                {
                    "path": event.src_path,
                    "message": f"File modified: {event.src_path}"
                }
            )
    
    def on_moved(self, event):
        """Handle file move event."""
        if not event.is_directory:
            self.logger.log_event(
                "FILE_ACCESS", 
                {
                    "path": event.src_path,
                    "dest_path": event.dest_path,
                    "message": f"File moved: {event.src_path} -> {event.dest_path}"
                }
            )

class FileChangeMonitor(BaseMonitor):
    """Monitor file system changes for security events."""
    
    def __init__(self, logger, watched_dirs):
        super().__init__(logger)
        self.watched_dirs = watched_dirs
        self.observers = []
    
    def run(self):
        """Set up and run file change monitoring."""
        try:
            # Create event handler
            event_handler = FileChangeEventHandler(self.logger)
            
            # Set up observers for each watched directory
            for directory in self.watched_dirs:
                if os.path.exists(directory):
                    observer = Observer()
                    observer.schedule(event_handler, directory, recursive=True)
                    observer.start()
                    self.observers.append(observer)
                else:
                    self.logger.log_event(
                        "MONITOR_WARNING", 
                        {"message": f"Watched directory does not exist: {directory}"}, 
                        level="WARNING"
                    )
            
            # Keep running until stopped
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring file changes: {str(e)}"}, 
                level="ERROR"
            )
        finally:
            # Stop all observers
            for observer in self.observers:
                observer.stop()
            
            # Wait for all observer threads to join
            for observer in self.observers:
                observer.join()
    
    def stop(self):
        """Stop the file change monitor."""
        super().stop()
        for observer in self.observers:
            observer.stop()
            observer.join()