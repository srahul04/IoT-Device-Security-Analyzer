import platform
import socket
import shutil
import os
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

def get_os_info():
    """Returns operating system information."""
    return {
        "system": platform.system(),
        "node_name": platform.node(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor()
    }

def get_hostname():
    """Returns the hostname of the system."""
    return socket.gethostname()

def get_disk_usage(path="/"):
    """Returns disk usage information for a given path."""
    try:
        total, used, free = shutil.disk_usage(path)
        return {
            "total": f"{total / (1024**3):.2f} GB",
            "used": f"{used / (1024**3):.2f} GB",
            "free": f"{free / (1024**3):.2f} GB",
            "percentage_used": f"{(used / total) * 100:.2f}%"
        }
    except Exception as e:
        return f"Error getting disk usage for {path}: {e}"

def get_logged_in_users():
    """Returns a list of logged-in users. (Platform-dependent) """
    users = []
    if platform.system() == "Windows":
        try:
            import subprocess
            # For Windows, 'query user' command can list logged-in users
            # This requires parsing output and might need admin rights for full details
            result = subprocess.run(["query", "user"], capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()
            # Skip header and parse lines
            for line in lines[1:]:
                parts = line.split()
                if len(parts) > 1:
                    users.append(parts[0]) # Username is usually the first part
        except Exception as e:
            users.append(f"Error getting Windows users: {e}")
    elif platform.system() == "Linux":
        try:
            import subprocess
            # On Linux, 'who' command can list logged-in users
            result = subprocess.run(["who"], capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()
            for line in lines:
                parts = line.split()
                if len(parts) > 0:
                    users.append(parts[0]) # Username is the first part
        except Exception as e:
            users.append(f"Error getting Linux users: {e}")
    else:
        users.append("User enumeration not supported on this OS.")
    return users

def get_system_info_fast():
    """Returns all system information quickly using concurrent operations."""
    results = {}
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        # Submit all system info gathering tasks concurrently
        future_os = executor.submit(get_os_info)
        future_hostname = executor.submit(get_hostname)
        future_disk = executor.submit(get_disk_usage, "C:/" if os.name == "nt" else "/")
        future_users = executor.submit(get_logged_in_users)
        
        # Collect results
        try:
            results["os_info"] = future_os.result()
        except Exception as e:
            results["os_info"] = {"error": str(e)}
            
        try:
            results["hostname"] = future_hostname.result()
        except Exception as e:
            results["hostname"] = f"Error: {e}"
            
        try:
            results["disk_usage"] = future_disk.result()
        except Exception as e:
            results["disk_usage"] = f"Error: {e}"
            
        try:
            results["logged_in_users"] = future_users.result()
        except Exception as e:
            results["logged_in_users"] = [f"Error: {e}"]
    
    return results

# Example Usage:
if __name__ == "__main__":
    print("--- OS Information ---")
    os_info = get_os_info()
    for key, value in os_info.items():
        print(f"{key}: {value}")

    print("\n--- Hostname ---")
    print(f"Hostname: {get_hostname()}")

    print("\n--- Disk Usage (C:/ or /) ---")
    if platform.system() == "Windows":
        disk_usage = get_disk_usage("C:/")
    else:
        disk_usage = get_disk_usage("/")

    if isinstance(disk_usage, dict):
        for key, value in disk_usage.items():
            print(f"{key}: {value}")
    else:
        print(disk_usage)

    print("\n--- Logged-in Users ---")
    users = get_logged_in_users()
    if users:
        for user in users:
            print(f"- {user}")
    else:
        print("No users logged in or unable to retrieve.")
