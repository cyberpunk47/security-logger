import threading
from typing import Dict, Any

class BaseMonitor:
    """Base class for all security monitors."""
    
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
    
    def start(self):
        """Start the monitor in a separate thread."""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """Stop the monitor."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
    
    def run(self):
        """Main monitoring loop to be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement run()")