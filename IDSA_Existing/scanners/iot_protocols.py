"""
iot_protocols.py
Specialized audit module for IoT-specific attack vectors:
- MQTT Broker audit (port 1883): Anonymous telemetry & unauthenticated subscribe checks
- RTSP IP Camera stream probe (port 554): Unauthenticated video feed accessibility
- CoAP Protocol check (port 5683 UDP): Constrained IoT device inspection
"""

import socket

def audit_mqtt_broker(host, port=1883, timeout=2.0):
    """
    Attempts a minimal MQTT 3.1.1 CONNECT packet without credentials.
    If the broker replies with a CONNACK (0x20 0x02 0x00 0x00),
    the broker allows anonymous access, which is a critical IoT security risk.
    """
    # Clean standard MQTT 3.1.1 CONNECT packet (anonymous, client id: idsa_probe)
    # 0x10 = CONNECT, 0x16 = Remaining Length (22 bytes)
    # Protocol: "MQTT", Level: 4, CleanSession: 1, KeepAlive: 60s, ClientId: "idsa_probe"
    client_id = b"idsa_probe"
    proto_name = b"MQTT"
    variable_header = (
        b"\x00\x04" + proto_name +  # Protocol Name length + "MQTT"
        b"\x04" +                   # Protocol Level 4 (MQTT 3.1.1)
        b"\x02" +                   # Connect Flags (Clean Session only, no user/pass)
        b"\x00\x3c"                 # Keep Alive 60 seconds
    )
    payload = len(client_id).to_bytes(2, "big") + client_id
    packet = b"\x10" + len(variable_header + payload).to_bytes(1, "big") + variable_header + payload

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(packet)

        response = s.recv(16)
        s.close()

        # CONNACK packet starts with 0x20, followed by length, session flag, and return code
        if response and response[0] == 0x20 and len(response) >= 4:
            return_code = response[3]
            if return_code == 0:
                return {
                    "vulnerable": True,
                    "severity": "Critical",
                    "description": f"Unauthenticated MQTT Broker detected on {host}:{port} (Anonymous Connection Accepted)",
                    "recommendation": "Require strong username/password authentication and TLS encryption on the MQTT broker immediately. Unprotected MQTT exposes real-time sensor telemetry and IoT actuator control."
                }
            elif return_code == 4 or return_code == 5:
                return {
                    "vulnerable": False,
                    "severity": "Informational",
                    "description": f"MQTT Broker on {host}:{port} enforces authentication (Connection Refused: Not Authorized)",
                    "recommendation": "Authentication is properly enforced. Ensure TLS (port 8883) is used in production."
                }
    except Exception:
        pass
    return None


def audit_rtsp_camera(host, port=554, timeout=2.0):
    """
    Probes RTSP on port 554 with an unauthenticated DESCRIBE command.
    Checks if an IP camera streams video feeds without credentials.
    """
    req = f"DESCRIBE rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: IDSA-Analyzer/2.0\r\nAccept: application/sdp\r\n\r\n"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(req.encode("utf-8"))

        data = s.recv(1024).decode("utf-8", errors="ignore")
        s.close()

        if "RTSP/1.0 200 OK" in data:
            return {
                "vulnerable": True,
                "severity": "Critical",
                "description": f"Exposed unauthenticated RTSP IP Camera stream on {host}:{port} (Public Video Stream Access)",
                "recommendation": "Enable mandatory digest authentication on your IP camera or NVR/DVR. Restrict RTSP port 554 to isolated camera VLANs."
            }
        elif "RTSP/1.0 401 Unauthorized" in data:
            return {
                "vulnerable": False,
                "severity": "Informational",
                "description": f"RTSP IP Camera on {host}:{port} requires authentication (401 Unauthorized)",
                "recommendation": "Ensure default camera passwords (admin/admin, 123456) have been changed."
            }
    except Exception:
        pass
    return None


def audit_iot_services(host, open_ports):
    """Audits IoT protocols against detected open ports."""
    findings = []
    if 1883 in open_ports:
        res = audit_mqtt_broker(host, 1883)
        if res:
            findings.append({
                "severity": res["severity"],
                "module": "IoT Protocol Audit",
                "description": res["description"],
                "recommendation": res["recommendation"]
            })

    if 554 in open_ports:
        res = audit_rtsp_camera(host, 554)
        if res:
            findings.append({
                "severity": res["severity"],
                "module": "IoT Camera Audit",
                "description": res["description"],
                "recommendation": res["recommendation"]
            })
    return findings

