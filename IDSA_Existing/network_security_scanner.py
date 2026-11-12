"""
network_security_scanner.py
Deeper host & network posture checks that traditional AVs ignore:
- DNS Hijack / Rouge DNS server detection
- ARP table poisoning / duplicate MAC analysis
- Active listening ports mapped to owning PIDs and process names
- Firewall profile status (Domain, Private, Public)
"""

import subprocess
import platform
import socket
import re

def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=12, shell=True)
        return r.stdout.strip()
    except Exception:
        return ""

def check_dns_servers():
    findings = []
    dns_servers = []
    if platform.system() == "Windows":
        out = _run("netsh interface ip show dns")
        # Extract IP addresses configured for DNS
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out)
        dns_servers = list(dict.fromkeys(ips))
        
        # Check for loopback or suspect non-routable configurations
        for ip in dns_servers:
            if ip.startswith("127."):
                findings.append({
                    "severity": "Medium",
                    "module": "Network Posture",
                    "description": f"DNS configured to loopback ({ip}) - could indicate local proxy or interception tool.",
                    "recommendation": "Verify whether a local resolver or security tool (e.g. Pi-hole/stub resolver) is intended. Otherwise reset DNS to DHCP or 1.1.1.1."
                })
    return {"dns_servers": dns_servers, "findings": findings}

def check_arp_table():
    """Detects potential ARP spoofing / duplicate MAC mappings."""
    findings = []
    if platform.system() == "Windows":
        out = _run("arp -a")
        mac_to_ips = {}
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\w+)", line)
            if m:
                ip, mac, entry_type = m.groups()
                mac = mac.lower().replace("-", ":")
                if mac in ("ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:16", "01:00:5e:7f:ff:fa"):
                    continue
                if mac not in mac_to_ips:
                    mac_to_ips[mac] = []
                mac_to_ips[mac].append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                findings.append({
                    "severity": "High",
                    "module": "Network Posture",
                    "description": f"Possible ARP spoofing/poisoning: Multiple IPs ({', '.join(ips)}) share MAC address {mac}",
                    "recommendation": "Inspect switch port security and check for unauthorized machines spoofing gateway or peer identities."
                })
    return findings

def check_firewall_status():
    findings = []
    statuses = {}
    if platform.system() == "Windows":
        out = _run("netsh advfirewall show allprofiles state")
        for line in out.splitlines():
            if "Profile Settings:" in line:
                profile = line.split()[0]
            elif "State" in line:
                state = line.split()[-1]
                statuses[profile] = state
                if state.upper() != "ON":
                    findings.append({
                        "severity": "High",
                        "module": "Network Posture",
                        "description": f"Windows Firewall {profile} profile is DISABLED",
                        "recommendation": f"Turn on Windows Firewall immediately: 'netsh advfirewall set {profile.lower()}profile state on'"
                    })
    return {"profiles": statuses, "findings": findings}

def get_listening_services():
    """Maps listening TCP/UDP ports to owning PID and process name."""
    services = []
    findings = []
    try:
        import psutil
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" or conn.type == socket.SOCK_DGRAM:
                pid = conn.pid
                pname = "unknown"
                if pid:
                    try:
                        pname = psutil.Process(pid).name()
                    except Exception:
                        pass
                services.append({
                    "proto": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "port": conn.laddr.port,
                    "ip": conn.laddr.ip,
                    "pid": pid,
                    "process": pname
                })
    except Exception:
        pass

    # Flag unencrypted protocols bound to all interfaces 0.0.0.0
    risky_ports = {21: "FTP", 23: "Telnet", 80: "HTTP", 445: "SMB", 3389: "RDP"}
    for s in services:
        if s["ip"] in ("0.0.0.0", "::") and s["port"] in risky_ports:
            findings.append({
                "severity": "Medium",
                "module": "Network Posture",
                "description": f"Publicly bound insecure service {risky_ports[s['port']]} on port {s['port']} (Process: {s['process']}, PID: {s['pid']})",
                "recommendation": f"Restrict port {s['port']} ({risky_ports[s['port']]}) to localhost/VPN or terminate process '{s['process']}' if not needed."
            })

    return {"services": services[:40], "findings": findings}

def run_network_security_scan():
    dns_res = check_dns_servers()
    arp_vulns = check_arp_table()
    fw_res = check_firewall_status()
    srv_res = get_listening_services()

    all_findings = []
    all_findings.extend(dns_res["findings"])
    all_findings.extend(arp_vulns)
    all_findings.extend(fw_res["findings"])
    all_findings.extend(srv_res["findings"])

    return {
        "dns": dns_res["dns_servers"],
        "firewall": fw_res["profiles"],
        "listening_count": len(srv_res["services"]),
        "findings": all_findings
    }
