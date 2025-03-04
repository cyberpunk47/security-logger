import time
import socket
import psutil
from .base_monitor import BaseMonitor

class NetworkMonitor(BaseMonitor):
    """Monitor network connections and changes."""
    
    def __init__(self, logger):
        super().__init__(logger)
        self.connections_cache = {}
    
    def run(self):
        """Monitor network connections."""
        try:
            # Record initial state
            self.connections_cache = self.get_network_connections()
            self.log_network_interfaces()
            
            # Monitor for changes
            while self.running:
                # Get current connections
                current_connections = self.get_network_connections()
                
                # Check for new connections
                for conn_id, conn_info in current_connections.items():
                    if conn_id not in self.connections_cache:
                        self.log_new_connection(conn_info)
                
                # Update cache
                self.connections_cache = current_connections
                
                # Check every 5 seconds
                time.sleep(5)
                
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error monitoring network: {str(e)}"}, 
                level="ERROR"
            )
    
    def get_network_connections(self):
        """Get current network connections."""
        connections = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                # Skip connections with no remote address
                if not conn.raddr:
                    continue
                
                # Create a unique identifier for this connection
                conn_id = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                
                # Get process info
                proc_name = "unknown"
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except:
                        pass
                
                connections[conn_id] = {
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "status": conn.status,
                    "pid": conn.pid,
                    "process": proc_name
                }
        except:
            pass
        
        return connections
    
    def log_network_interfaces(self):
        """Log information about network interfaces."""
        try:
            for interface, addresses in psutil.net_if_addrs().items():
                for addr in addresses:
                    if addr.family == socket.AF_INET:  # IPv4
                        self.logger.log_event(
                            "NETWORK_INTERFACE", 
                            {
                                "message": f"Network interface: {interface} - {addr.address}",
                                "interface": interface,
                                "address": addr.address,
                                "netmask": addr.netmask
                            }
                        )
        except Exception as e:
            self.logger.log_event(
                "MONITOR_ERROR", 
                {"message": f"Error getting network interfaces: {str(e)}"}, 
                level="ERROR"
            )
    
    def log_new_connection(self, conn_info):
        """Log a new network connection."""
        # Determine if this is potentially suspicious
        is_suspicious = False
        remote_ip = conn_info["remote_address"].split(":")[0]
        
        # Check for common suspicious ports
        suspicious_ports = [22, 23, 3389, 4444, 5900]
        try:
            remote_port = int(conn_info["remote_address"].split(":")[1])
            if remote_port in suspicious_ports:
                is_suspicious = True
        except:
            pass
        
        details = {
            "message": f"New network connection: {conn_info['local_address']} -> {conn_info['remote_address']} ({conn_info['process']})",
            "local_address": conn_info["local_address"],
            "remote_address": conn_info["remote_address"],
            "process": conn_info["process"],
            "pid": conn_info["pid"]
        }
        
        # Log at appropriate level
        level = "WARNING" if is_suspicious else "INFO"
        self.logger.log_event("NETWORK_CONNECTION", details, level=level)