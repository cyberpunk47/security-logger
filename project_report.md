# Project Report: OS Security Event Logger

## Project Overview

The OS Security Event Logger is a Python-based security monitoring system designed to emulate Windows Event Log functionality on Linux systems. It provides real-time logging and analysis of security events, such as authentication attempts, process creation, file changes, and network activity. The project aims to enhance system administrators' ability to monitor and respond to potential security threats through a modern graphical interface and structured event logging.

Key Objectives:
- Real-time monitoring of critical system events.
- Graphical representation of security events for better analysis.
- Integration with the MITRE ATT&CK framework for threat categorization.
- Support for both terminal-based and GUI-based interaction.

---

## Module-Wise Breakdown

### 1. Event Monitoring Module
- **Description**: Monitors various system components for security-related events.
- **Submodules**:
  - **Authentication Log Monitor**:
    - Tracks login attempts, successful logins, and failed logins by parsing `/var/log/auth.log` or `/var/log/secure`.
    - Detects invalid user login attempts and sudo command executions.
  - **Auditd Monitor**:
    - Captures events from the Linux audit daemon using `ausearch`.
    - Maps audit events to Windows-style event types such as `USER_LOGIN_SUCCESS` and `PRIVILEGE_ESCALATION`.
  - **Syslog Monitor**:
    - Monitors system logs (`/var/log/syslog` or `/var/log/messages`) for service changes, firewall events, and package management activities.
    - Detects firewall rule changes and service start/stop events.
  - **Journald Monitor**:
    - Tracks systemd journal entries for privilege escalation, sudo commands, and session management.
    - Monitors services like `sshd`, `sudo`, and `firewalld`.
  - **File Change Monitor**:
    - Detects file creation, deletion, and modification in critical directories using the `watchdog` library.
    - Monitors directories such as `/etc`, `/bin`, and `/usr/bin`.
  - **Network Monitor**:
    - Logs new network connections and flags suspicious activity based on ports and reverse DNS lookups.
    - Detects connections to suspicious ports like `22`, `3389`, and `4444`.
  - **Process Monitor**:
    - Tracks process creation and termination.
    - Identifies suspicious commands such as `wget`, `curl`, and `nmap`.
    - Includes a dedicated `sudo` watcher to monitor privileged command executions.

### 2. Database Module
- **Description**: Handles structured storage of events in an SQLite database.
- **Features**:
  - Thread-safe operations with locking mechanisms.
  - Automatic database vacuuming to prevent size bloat.
  - Support for advanced queries and filtering.
  - Batch insertion for improved performance.

### 3. Graphical User Interface (GUI) Module
- **Description**: Provides a PyQt5-based interface for real-time event visualization.
- **Features**:
  - Event table with filtering and sorting options.
  - Statistical charts for event type distribution and timeline analysis.
  - Theme customization (dark and light modes).
  - CSV export functionality for external analysis.
  - Real-time updates with background workers to prevent UI freezing.

### 4. Configuration and Privilege Management
- **Description**: Manages application settings and ensures proper permissions for monitoring.
- **Features**:
  - Configuration file for customizable settings.
  - `run_with_admin.py` script for handling elevated privileges.
  - Support for systemd service installation.
  - Methods to handle X11 display permissions for GUI when running as root.

---

## Functionalities

1. **Real-Time Security Event Logging**:
   - Captures and logs events such as user logins, file changes, and network connections.
   - Maps events to Windows-style event IDs for familiarity.

2. **Process Management**:
   - Tracks process creation and termination.
   - Identifies suspicious commands and privilege escalation attempts.

3. **Graphical Event Representation**:
   - Displays events in a sortable table.
   - Provides statistical charts for event analysis.

4. **Database Management**:
   - Stores events in an SQLite database with efficient querying capabilities.

5. **Theme Support**:
   - Offers dark and light themes for better usability.

6. **Export Options**:
   - Allows exporting event data to CSV for external analysis.

7. **MITRE ATT&CK Integration**:
   - Maps events to MITRE ATT&CK techniques for better threat categorization.

---

## Technology Used

### Programming Languages:
- Python 3.8+

### Libraries and Tools:
- **PyQt5**: GUI framework for the graphical interface.
- **Matplotlib**: Statistical charting and visualization.
- **Pandas**: Data manipulation and analysis.
- **Psutil**: Process and system monitoring.
- **Watchdog**: File system monitoring.
- **Systemd-python**: Integration with systemd journal (Linux-specific).
- **SQLite3**: Database for event storage.
- **Python-dateutil**: Date and time utilities.

### Other Tools:
- **GitHub**: Version control and collaboration.
- **Systemd**: Service management for background monitoring.
- **xhost**: X11 display permission management.

---

## Flow Diagram

Below is the system workflow represented in an SVG-based flow diagram:

```svg
<!-- filepath: /home/aman/security_event_logger/flow_diagram.svg -->
<svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">
  <rect x="50" y="50" width="200" height="50" fill="#4CAF50" stroke="#000" />
  <text x="150" y="80" font-size="14" text-anchor="middle" fill="#fff">Event Monitoring</text>
  
  <rect x="300" y="50" width="200" height="50" fill="#2196F3" stroke="#000" />
  <text x="400" y="80" font-size="14" text-anchor="middle" fill="#fff">Database Module</text>
  
  <rect x="550" y="50" width="200" height="50" fill="#FFC107" stroke="#000" />
  <text x="650" y="80" font-size="14" text-anchor="middle" fill="#fff">GUI Module</text>
  
  <line x1="250" y1="75" x2="300" y2="75" stroke="#000" stroke-width="2" />
  <line x1="500" y1="75" x2="550" y2="75" stroke="#000" stroke-width="2" />
</svg>
```

---

## Revision Tracking on GitHub

- **Repository Name**: OS-Security-Event-Logger
- **GitHub Link**: [https://github.com/cyberpunk47/security-logger](https://github.com/cyberpunk47/security-logger)

---

## Errors Encountered

1. **Incorrect Event Values**:
   - Issue: Some event values were incorrectly parsed from logs.
   - Solution: Improved regex patterns for log parsing.

2. **UI Freezing**:
   - Issue: The GUI became unresponsive during high event volumes.
   - Solution: Added background workers for data processing.

3. **Inconsistent Event Formatting**:
   - Issue: Event descriptions lacked uniformity.
   - Solution: Standardized event descriptions using templates.

4. **Permission-Related Problems**:
   - Issue: Monitoring certain logs required elevated privileges.
   - Solution: Added `run_with_admin.py` script and xhost-based permission handling.

---

## Conclusion and Future Scope

### Conclusion:
The OS Security Event Logger successfully provides a comprehensive solution for monitoring and analyzing security events on Linux systems. Its modular design, real-time capabilities, and user-friendly GUI make it a valuable tool for system administrators.

### Future Scope:
1. **Role-Based Access Control**:
   - Implement user roles for accessing specific features.

2. **AI-Based Anomaly Detection**:
   - Use machine learning to identify unusual patterns in security events.

3. **Log Export Options**:
   - Add support for exporting logs to SIEM systems.

4. **Web-Based Dashboard**:
   - Develop a web interface for remote monitoring.

---

## References

1. [PyQt5 Documentation](https://www.riverbankcomputing.com/software/pyqt/)
2. [Linux Audit Framework Documentation](https://github.com/linux-audit/audit-documentation)
3. [MITRE ATT&CK Framework](https://attack.mitre.org/)
4. [SQLite Documentation](https://www.sqlite.org/docs.html)
5. [Systemd Journal Documentation](https://www.freedesktop.org/software/systemd/man/systemd-journald.service.html)

---

## Appendix

### A. AI-Generated Project Elaboration/Breakdown Report
[Paste AI-generated details here.]

### B. Problem Statement
[Provide a clear problem definition here.]

