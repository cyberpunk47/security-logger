# File: gui.py
# Security Event Logger - GUI Launcher
# Initializes and launches the graphical user interface
import sys
import os
import subprocess
from PyQt5.QtWidgets import QApplication
from main_window import MainWindow
from security_logger import SecurityEventLogger
import logging

# Near the top of gui.py, before creating the QApplication
if os.geteuid() == 0:  # If running as root
    # Check if we're on Wayland or X11
    display = os.environ.get('DISPLAY')
    wayland_display = os.environ.get('WAYLAND_DISPLAY')
    
    # Force xcb (X11) when running as root for better compatibility
    os.environ['QT_QPA_PLATFORM'] = 'xcb'
    print("Forcing X11/xcb platform for root")
    
    # Try to set X11 permissions
    try:
        subprocess.call(['xhost', '+local:root'])
        print("X11 access granted to root user")
    except Exception as e:
        print(f"Warning: Could not set X11 permissions: {e}")

def main():
    # Determine the appropriate log file location based on permissions
    if os.geteuid() == 0:  # Running as root
        log_dir = '/var/log/security_event_logger'
        log_file = os.path.join(log_dir, 'gui.log')
        # Create log directory if needed
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception:
                # Fall back to user directory if we can't create the system directory
                log_file = os.path.expanduser('~/.local/share/security_event_logger/gui.log')
    else:
        # Use user's home directory when not running as root
        log_dir = os.path.expanduser('~/.local/share/security_event_logger')
        log_file = os.path.join(log_dir, 'gui.log')
    
    # Ensure the log directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    try:
        # Redirect stdout and stderr to the log file
        sys.stdout = open(log_file, 'a')
        sys.stderr = open(log_file, 'a')
        
        # Set up logging - redirect to a file instead of console for GUI mode
        logging.basicConfig(
            filename=log_file,
            level=logging.WARNING,  # Reduce noise by only showing warnings and errors
            format='%(asctime)s [%(levelname)s] %(message)s'
        )
    except (IOError, PermissionError) as e:
        print(f"Warning: Could not open log file: {e}. Logging to console only.")
    
    # Configure root logger to be less verbose
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)
    
    # Create GUI app
    app = QApplication(sys.argv)
    
    # Create logger with GUI mode enabled
    logger = SecurityEventLogger(config_file=None, gui_mode=True)
    
    # Create main window
    window = MainWindow(logger)
    
    # Start monitoring after UI is ready
    logger.start()
    
    # Show the window and start the event loop
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()