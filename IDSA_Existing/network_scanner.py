import platform
import subprocess
import socket
import ipaddress
import concurrent.futures
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

def ping_host(host, count=1, timeout=1):
    """Pings a host and returns True if reachable, False otherwise."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        command = ['ping', param, str(count), '-w', str(int(timeout * 1000)), host] if platform.system().lower() == 'windows' else ['ping', param, str(count), '-W', str(timeout), host]
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 1)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def scan_port(host, port, timeout=0.5):
    """Scans a single port on a host and returns True if open, False otherwise."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_local_ip():
    """Returns the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1" # Fallback to loopback if no network connection

def get_network_range(ip_address):
    """Determines the network range based on the local IP address (e.g., 192.168.1.0/24)."""
    try:
        # Assuming a default /24 subnet for simplicity for local networks
        # In a real scenario, you might want to get the actual subnet mask
        network = ipaddress.ip_network(f"{ip_address}/24", strict=False)
        return str(network)
    except Exception:
        return None

def ping_sweep(network_range, max_workers=50):
    """Performs a fast concurrent ping sweep on the given network range to discover active hosts."""
    active_hosts = []
    if not network_range:
        return active_hosts

    try:
        network = ipaddress.ip_network(network_range)
        hosts = [str(host) for host in network.hosts()]
        
        # Use ThreadPoolExecutor for concurrent ping operations
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all ping tasks
            future_to_host = {
                executor.submit(ping_host, host, count=1, timeout=0.3): host 
                for host in hosts
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    if future.result():
                        active_hosts.append(host)
                except Exception:
                    pass  # Skip failed pings silently
                    
    except Exception as e:
        active_hosts.append(f"Error during ping sweep: {e}")
    return active_hosts

def scan_open_ports(host, common_ports=None, max_workers=20):
    """Scans a host for open common ports using concurrent operations."""
    if common_ports is None:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]

    open_ports = []
    
    # Use ThreadPoolExecutor for concurrent port scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all port scan tasks
        future_to_port = {
            executor.submit(scan_port, host, port, timeout=0.2): port 
            for port in common_ports
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass  # Skip failed port scans silently
                
    return open_ports

def fast_network_scan(network_range=None, max_workers=50):
    """Performs a complete fast network scan with concurrent operations."""
    if network_range is None:
        local_ip = get_local_ip()
        network_range = get_network_range(local_ip)
    
    if not network_range:
        return {"error": "Could not determine network range"}
    
    # Fast ping sweep
    active_hosts = ping_sweep(network_range, max_workers)
    
    # Concurrent port scanning for all active hosts
    scan_results = {}
    if active_hosts:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(active_hosts))) as executor:
            future_to_host = {
                executor.submit(scan_open_ports, host, max_workers=20): host 
                for host in active_hosts
            }
            
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    open_ports = future.result()
                    scan_results[host] = open_ports
                except Exception as e:
                    scan_results[host] = f"Error: {e}"
    
    return {
        "network_range": network_range,
        "active_hosts": active_hosts,
        "scan_results": scan_results
    }

# Example Usage:
if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"Local IP: {local_ip}")

    network_range = get_network_range(local_ip)
    print(f"Network Range: {network_range}")

    print("\n--- Ping Sweep ---")
    active_hosts = ping_sweep(network_range)
    if active_hosts:
        print("Active Hosts:")
        for host in active_hosts:
            print(f"- {host}")

            print(f"  Scanning common ports for {host}...")
            open_ports = scan_open_ports(host)
            if open_ports:
                print(f"    Open Ports: {open_ports}")
            else:
                print("    No common open ports found.")
    else:
        print("No active hosts found in the network range.")
