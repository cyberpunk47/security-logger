# File: base_monitor.py
# Security Event Logger - Base Monitor Class
# Abstract base class for all security event monitors
import threading
from typing import Any

class BaseMonitor(threading.Thread):
    """Base class for all security monitors."""
    
    def __init__(self, logger):
        """Initialize the monitor with a logger."""
        threading.Thread.__init__(self, daemon=True)
        self.logger = logger
        self.running = False
    
    def run(self):
        """Run the monitor. To be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement the run method")
    
    def start(self):
        """Start the monitor."""
        self.running = True
        super().start()
    
    def stop(self):
        """Stop the monitor."""
        self.running = False