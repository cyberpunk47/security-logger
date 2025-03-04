# Import all monitor classes to make them available when importing the monitors package
from .base_monitor import BaseMonitor
from .auth_log_monitor import AuthLogMonitor
from .auditd_monitor import AuditdMonitor
from .syslog_monitor import SyslogMonitor
from .journald_monitor import JournaldMonitor
from .file_change_monitor import FileChangeMonitor
from .network_monitor import NetworkMonitor
from .process_monitor import ProcessMonitor

# Optional: Define __all__ to explicitly specify what should be imported when using `from monitors import *`
__all__ = [
    "BaseMonitor",
    "AuthLogMonitor",
    "AuditdMonitor",
    "SyslogMonitor",
    "JournaldMonitor",
    "FileChangeMonitor",
    "NetworkMonitor",
    "ProcessMonitor",
]