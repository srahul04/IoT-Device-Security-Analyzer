"""
iot_discovery.py
Active IoT discovery module via SSDP (UPnP) and mDNS broadcast probing.
Finds exact device names, models, manufacturers, and service XML URLs
without guessing MAC prefixes.
"""

import socket
import re
import urllib.request
import xml.etree.ElementTree as ET

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 2
SSDP_MSG = (
    'M-SEARCH * HTTP/1.1\r\n'
    f'HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n'
    'MAN: "ssdp:discover"\r\n'
    f'MX: {SSDP_MX}\r\n'
    'ST: ssdp:all\r\n'
    '\r\n'
).encode("utf-8")


def discover_ssdp(timeout=2.5):
    """
    Broadcasts SSDP M-SEARCH packet to discover UPnP-enabled IoT devices
    (Smart TVs, Cameras, Printers, Routers, Smart Speakers, Home Automation).
    Returns list of discovered device metadata dicts.
    """
    discovered = []
    seen_locations = set()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    # Set TTL
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    try:
        sock.sendto(SSDP_MSG, (SSDP_ADDR, SSDP_PORT))
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                response = data.decode("utf-8", errors="ignore")
                ip = addr[0]

                # Extract LOCATION header
                loc_match = re.search(r"LOCATION:\s*(http[s]?://[^\r\n]+)", response, re.IGNORECASE)
                server_match = re.search(r"SERVER:\s*([^\r\n]+)", response, re.IGNORECASE)
                st_match = re.search(r"ST:\s*([^\r\n]+)", response, re.IGNORECASE)
                usn_match = re.search(r"USN:\s*([^\r\n]+)", response, re.IGNORECASE)

                location = loc_match.group(1).strip() if loc_match else None
                server = server_match.group(1).strip() if server_match else "UPnP Device"
                service_type = st_match.group(1).strip() if st_match else ""
                usn = usn_match.group(1).strip() if usn_match else ""

                if location and location in seen_locations:
                    continue
                if location:
                    seen_locations.add(location)

                # Try to fetch device XML description if accessible
                device_info = _fetch_upnp_xml(location)

                discovered.append({
                    "ip": ip,
                    "protocol": "UPnP / SSDP",
                    "server": server,
                    "service_type": service_type,
                    "location": location,
                    "friendly_name": device_info.get("friendly_name", ""),
                    "manufacturer": device_info.get("manufacturer", ""),
                    "model_name": device_info.get("model_name", ""),
                    "model_number": device_info.get("model_number", ""),
                })
            except socket.timeout:
                break
            except Exception:
                break
    except Exception:
        pass
    finally:
        sock.close()

    return discovered


def _fetch_upnp_xml(url):
    """Safely retrieves device friendly name & model from UPnP XML descriptor."""
    info = {}
    if not url:
        return info
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IDSA-Security-Scanner/2.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            xml_data = resp.read()
            root = ET.fromstring(xml_data)
            # Remove namespace prefixes for easy parsing
            for elem in root.iter():
                if "}" in elem.tag:
                    elem.tag = elem.tag.split("}", 1)[1]

            def find_text(tag):
                node = root.find(f".//{tag}")
                return node.text.strip() if node is not None and node.text else ""

            info["friendly_name"] = find_text("friendlyName")
            info["manufacturer"] = find_text("manufacturer")
            info["model_name"] = find_text("modelName")
            info["model_number"] = find_text("modelNumber")
    except Exception:
        pass
    return info


def run_iot_discovery():
    devices = discover_ssdp()
    findings = []

    for d in devices:
        name = d.get("friendly_name") or d.get("model_name") or d.get("server")
        findings.append({
            "severity": "Informational",
            "module": "IoT UPnP Discovery",
            "description": f"UPnP/SSDP broadcasting IoT device: '{name}' at {d['ip']} ({d.get('manufacturer', 'Generic')})",
            "recommendation": "If UPnP is not required on this network segment, disable UPnP in the device settings to prevent automated port-mapping exploits (UPnProxy)."
        })

    return {
        "discovered_devices": devices,
        "findings": findings
    }

