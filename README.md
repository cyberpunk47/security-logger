# Windows-Style Security Event Logger for Linux
A Python-based security event monitoring system for Linux that emulates Windows Event Log functionality. Captures and logs security-related events in a structured format, complete with Windows-style event IDs and categories.
![Project Structure](assets/demo.jpg) <!-- Screenshot -->
---
## Features
- **Windows Event Log Formatting**  
  Logs events with familiar Windows Event IDs (e.g., `4624` for successful logins) and types (Information, Warning, Error).
- **Dual Interface**  
  Run in **terminal mode** (`security_logger.py`) for CLI operations or launch the **GUI** (`gui.py`) for visual interaction.
- **Real-Time Monitoring**  
  Tracks authentication logs, file changes, network activity, and processes.
- **SQLite Database**  
  Stores events in `/var/log/securityevents.db` by default for query and analysis.
- **Systemd Service**  
  Supports installation as a background service for 24/7 monitoring.
- **Theme Support**
  Customizable dark and light themes for the GUI interface.
- **Thread-Safe Operations**
  Enhanced database operations with proper thread locks for improved stability.
- **Background Data Processing**
  UI responsiveness improvements with background data refresh workers.
---

## Recent Updates
- **GUI Framework Migration**: Migrated from tkinter to PyQt5 for a more modern and responsive interface
- **Data Analysis Improvements**: Integrated pandas for efficient data handling and manipulation
- **Enhanced Visualizations**: Added matplotlib for improved statistical charts and event analysis
- **Enhanced GUI Display Support**: Fixed X11 display connection issues when running with sudo
- **Theme Customization**: Added full dark/light theme support for better visibility
- **Thread Safety Improvements**: Enhanced database operations with proper thread locks
- **Performance Optimization**: Improved UI responsiveness with background data refresh workers
- **Better Error Handling**: Enhanced error feedback and system integration
- **Multiple Admin Methods**: Added several methods to run with elevated privileges
- **Database Optimization**: Added automatic vacuuming to prevent database bloat
- **Statistical Visualizations**: Improved charts and data representation

### Technology Transition
The project has undergone significant technological updates:
- **GUI**: Migrated from basic tkinter to modern PyQt5 for better UX and theme support
- **Data Processing**: Added pandas for efficient data manipulation and filtering
- **Visualization**: Integrated matplotlib for advanced charting and event analysis
- **Threading**: Improved multi-threading support for background processing
- **System Integration**: Better integration with X11 display server and systemd

---
## Installation
### Prerequisites
- **Python 3.8+**
- **System Packages** (for full functionality):
  ```bash
  # For Debian/Ubuntu
  sudo apt install auditd systemd python3-tk
  # For Fedora
  sudo dnf install audit systemd python3-tkinter
  ```
### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/security-event-logger.git
   cd security-event-logger
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. **Configure the application**:
   ```bash
   # Copy the default configuration file
   cp config/default_config.ini config/config.ini
   # Edit the config file if needed (e.g., database path)
   nano config/config.ini
   ```
5. **Set Permissions** (if using default `/var/log` paths):
   ```bash
   sudo mkdir -p /var/log
   sudo touch /var/log/securityevents.{db,log}
   sudo chown $USER:$USER /var/log/securityevents.*
   ```
6. **Verify Installation**:
   ```bash
   # Run in terminal mode
   python security_logger.py --verbose
   # Test GUI (requires tkinter)
   python gui.py
   ```
---
## Usage
### Terminal Mode (CLI)
```bash
# Start the logger in terminal
python security_logger.py [--verbose|--daemon|--list-events|--search]
# Examples:
python security_logger.py --verbose          # Debug mode
python security_logger.py --list-events      # Show recent 100 events
python security_logger.py --search "event_id = '4625'"  # Filter failed logins
```
### GUI Mode
```bash
# Launch the graphical interface
python gui.py
```
> **Note**: Some features in the GUI are still under development. For the most stable experience, use the terminal mode.

### Running With Elevated Privileges
The Security Event Logger requires root access to monitor many system logs. There are several ways to run with elevated privileges:

#### Method 1: Using xhost (Recommended for GUI)
```bash
# Allow root to access X server (temporarily)
xhost +local:root
# Run the application
sudo /path/to/venv/bin/python /path/to/security_event_logger/gui.py
# Restore X server security
xhost -local:root
```

#### Method 2: Using sudo -E
```bash
# Run with sudo while preserving environment variables
sudo -E /path/to/venv/bin/python /path/to/security_event_logger/gui.py
```

#### Method 3: Using the run_with_admin script
```bash
sudo /path/to/venv/bin/python /path/to/security_event_logger/run_with_admin.py
```

### Systemd Service
```bash
# Install and start as a background service (requires root)
sudo python security_logger.py --install-service
sudo systemctl status seclog.service         # Verify status
```
---

## Notes on GUI and Terminal Issues
### GUI Issues
1. **X11 Display Errors**:
   - When running with sudo, you may encounter X server connection errors
   - Use one of the methods listed above in the "Running With Elevated Privileges" section
   - Normal messages like `QStandardPaths: XDG_RUNTIME_DIR not set` can be safely ignored

2. **PyQt5 Dependencies**:
   - The GUI now uses PyQt5 instead of tkinter
   - If you encounter errors, ensure all dependencies are installed:
     ```bash
     pip install -r requirements.txt
     ```

3. **GUI Performance**:
   - With high volumes of events, the GUI may become less responsive
   - Use the filtering options to limit the displayed events
   - Statistical visualizations are resource-intensive and are only updated when that tab is active

4. **Theme Issues**:
   - If themes don't load correctly, check the assets/themes directory
   - You can switch between dark and light themes from the dropdown menu

### Terminal Issues
1. **Permission Denied**:
   - If running without root privileges, some events (e.g., `auditd`, `journald`) may not be captured.
   - Run with `sudo` for full functionality:
     ```bash
     sudo python security_logger.py --verbose
     ```
2. **Database Locked**:
   - If the database file (`/var/log/securityevents.db`) is locked, ensure no other instance of the logger is running.
   - Restart the application or delete the database file (if not needed).
3. **Missing Logs**:
   - Ensure the monitored log files (e.g., `/var/log/auth.log`) exist and are readable.
   - Adjust the `config.ini` file to include valid paths.
---
## Known Limitations and Work in Progress
- **Advanced Event Correlation**: Machine learning-based correlation features are under development
- **Remote Monitoring**: Support for monitoring multiple systems from a central console is planned
- **SIEM Integration**: Export capabilities for SIEM systems are in progress
- **Resource Usage**: Intensive monitoring may increase CPU and memory usage
- **GUI Stability**: The GUI interface may crash under certain conditions - this is being addressed
- **Database Growth**: The database can grow large over time - automatic cleanup is being improved

---
## Project Structure
```
.
├── config/               # Configuration files
│   ├── default_config.ini  # Template configuration
│   └── config.ini          # Active configuration (create via setup)
├── monitors/             # Monitoring modules (auth logs, network, etc.)
├── event_database.py     # SQLite database handler
├── security_logger.py    # Terminal-mode application
├── gui.py                # Graphical User Interface (WIP)
└── logs/                 # Log storage directory
```
---
## Maintainers
- [Yasir Hameed](https://github.com/cyberpunk47) (Developer)
- [Md Aquib Raza](https://github.com/razaaquib99) (Developer)
---
## Contributing
1. Fork the repository.
2. Create a feature branch:  
   `git checkout -b feature/your-feature`
3. Commit changes:  
   `git commit -m 'Add some feature'`
4. Push to the branch:  
   `git push origin feature/your-feature`
5. Open a **Pull Request**.
---
## License
MIT License. See [LICENSE](LICENSE) for details.
