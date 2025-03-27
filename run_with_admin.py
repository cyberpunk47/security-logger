#!/usr/bin/env python3
import sys
import os
import subprocess
import importlib.util
import site

def check_module(module_name):
    """Check if a Python module is available."""
    return importlib.util.find_spec(module_name) is not None

def install_module(module_name):
    """Install a Python module using pip."""
    print(f"Installing {module_name}...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
    
def ensure_dependencies():
    """Make sure all required dependencies are available."""
    required_modules = [
        "pandas",
        "matplotlib",
        "psutil",
        "watchdog",
        "PyQt5",
        "python-dateutil",
    ]
    
    # Try to install systemd if on Linux (optional)
    if sys.platform == 'linux':
        required_modules.append("systemd-python")
    
    missing = []
    for module in required_modules:
        if not check_module(module.split('>=')[0]):
            missing.append(module)
    
    if missing:
        print(f"Installing missing dependencies: {missing}")
        for module in missing:
            install_module(module)
        print("All dependencies installed successfully.")

def main():
    # Change to the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Make sure we have all needed packages
    ensure_dependencies()
    
    # Add the current directory to the Python path
    sys.path.insert(0, script_dir)
    
    # Run the GUI with the current Python interpreter
    from gui import main
    main()

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("This script needs to be run with admin privileges.")
        sys.exit(1)
        
    main()
