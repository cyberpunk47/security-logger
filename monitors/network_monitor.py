import time
import psutil
import socket
from .base_monitor import BaseMonitor

class NetworkMonitor(BaseMonitor):
    """Monitor network connections for security events."""
    
    def __init__(self, logger):
        super().__init__(logger)
        self.connection_cache = set()
    
    def run(self):
        """Monitor network connections for security events."""
        try:
            # Get initial connections
            self.connection_cache = self.get_connection_keys()
            
            # Brief pause to let system stabilize
            time.sleep(1)
            
            # Monitor for changes
            while self.running:
                # Get current connections
                current_connections = self.get_connection_keys()
                
                # Find new connections
                new_connections = current_connections - self.connection_cache
                
                # Process new connections
                for conn_key in new_connections:
                    self.log_new_connection(conn_key)
                
                # Update cache
                self.connection_cache = current_connections
                
                time.sleep(1)  # Check every second
                
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring network: {str(e)}"}, 
                level="ERROR"
            )
    
    def get_connection_keys(self):
        """Get a set of connection keys for the current network connections."""
        connections = set()
        
        for conn in psutil.net_connections(kind='inet'):
            # Skip connections with no remote address
            if not conn.raddr:
                continue
            
            # Create a unique key for this connection
            conn_key = (
                conn.laddr.ip,
                conn.laddr.port,
                conn.raddr.ip,
                conn.raddr.port,
                conn.status,
                conn.pid if conn.pid else 0
            )
            
            connections.add(conn_key)
        
        return connections
    
    def log_new_connection(self, conn_key):
        """Log a new network connection."""
        local_ip, local_port, remote_ip, remote_port, status, pid = conn_key
        
        # Try to get process information
        process_name = "unknown"
        username = "unknown"
        
        if pid:
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                username = process.username()
            except:
                pass
        
        # Try to perform reverse DNS lookup (with timeout)
        remote_hostname = remote_ip
        try:
            remote_hostname = socket.gethostbyaddr(remote_ip)[0]
        except:
            pass
        
        # Determine if this is potentially suspicious
        is_suspicious = False
        
        # Check for common suspicious ports
        suspicious_ports = {22, 23, 3389, 4444, 5900, 8080, 1080, 9050}
        if remote_port in suspicious_ports or local_port in suspicious_ports:
            is_suspicious = True
        
        # Create message
        message = f"New {status} connection: {local_ip}:{local_port} -> {remote_ip}:{remote_port}"
        if process_name != "unknown":
            message += f" (Process: {process_name}, PID: {pid})"
        
        # Create details
        details = {
            "message": message,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "remote_hostname": remote_hostname,
            "status": status,
            "pid": pid,
            "process": process_name,
            "username": username
        }
        
        # Determine level based on suspiciousness
        level = "WARNING" if is_suspicious else "INFO"
        
        # Log the event
        self.logger.log_event("NETWORK_CONNECTION", details, level=level)