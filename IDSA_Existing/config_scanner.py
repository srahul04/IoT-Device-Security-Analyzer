import platform
import os

# For demonstration purposes, a small list of common weak passwords/usernames.
# In a real-world scenario, this would be a much larger dictionary or a more sophisticated approach.
WEAK_CREDENTIALS = {
    "admin": ["admin", "password", "123456"],
    "root": ["root", "password", "123456"],
    "user": ["user", "password", "123456"],
}

# Common ports often associated with potentially exposed services if unsecurely configured
EXPOSED_SERVICE_PORTS = {
    21: "FTP (File Transfer Protocol) - Often allows anonymous access or weak credentials.",
    23: "Telnet - Sends data in plain text, susceptible to eavesdropping.",
    80: "HTTP (Hypertext Transfer Protocol) - Unencrypted web traffic, sensitive data exposed.",
    443: "HTTPS (Hypertext Transfer Protocol Secure) - Check for outdated TLS versions or weak ciphers.",
    445: "SMB (Server Message Block) - Often targeted for ransomware and exploits (e.g., EternalBlue).",
    3389: "RDP (Remote Desktop Protocol) - Brute-force target, can be vulnerable to CVEs."
}

def check_weak_passwords():
    """Simulates checking for weak default passwords on services (placeholder)."""
    vulnerabilities = []
    # This function would ideally interact with live services or configuration files.
    # For this demo, it's a symbolic check.
    for username, passwords in WEAK_CREDENTIALS.items():
        for password in passwords:
            # In a real scenario, attempt to authenticate to known services
            # For now, just a placeholder indication
            if username == "admin" and password == "password":
                vulnerabilities.append({
                    "severity": "High",
                    "description": f"Potential weak default credential found: {username}/{password} (Example)."
                })
                break # Only report once per username for this demo
    return vulnerabilities

def check_exposed_services(open_ports_results):
    """Checks for potentially exposed services based on a list of open ports."""
    vulnerabilities = []
    for host, ports in open_ports_results.items():
        for port in ports:
            if port in EXPOSED_SERVICE_PORTS:
                vulnerabilities.append({
                    "severity": "Medium",
                    "description": f"Potentially exposed service on {host}:{port} - {EXPOSED_SERVICE_PORTS[port]}"
                })
    return vulnerabilities

def scan_configuration_issues(network_scan_results=None):
    """Performs a comprehensive scan for configuration issues."""
    all_vulnerabilities = []

    # Check for weak passwords
    all_vulnerabilities.extend(check_weak_passwords())

    # Check for exposed services if network scan results are available
    if network_scan_results:
        # network_scan_results is expected to be a dict of {host: [open_ports]}
        all_vulnerabilities.extend(check_exposed_services(network_scan_results))

    return all_vulnerabilities

# Example Usage:
if __name__ == "__main__":
    print("--- Configuration Scan ---")

    # Dummy network scan results for testing exposed services
    dummy_network_scan_results = {
        "192.168.1.1": [21, 80],
        "192.168.1.100": [22],
        "192.168.1.5": [23, 445],
    }

    config_issues = scan_configuration_issues(dummy_network_scan_results)
    if config_issues:
        for issue in config_issues:
            print(f"[{issue['severity']}] {issue['description']}")
    else:
        print("No configuration issues found.")
