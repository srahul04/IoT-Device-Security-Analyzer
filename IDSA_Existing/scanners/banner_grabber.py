"""
banner_grabber.py
Service banner grabber and HTTP title/header extractor.
Replaces port guessing with real fingerprinting for HTTP, HTTPS, SSH, FTP, Telnet, and RTSP.
"""

import socket
import ssl
import re

COMMON_PROBES = {
    21:   b"HELP\r\n",
    22:   b"",
    23:   b"",
    80:   b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: IDSA-Analyzer/2.0\r\nConnection: close\r\n\r\n",
    443:  b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: IDSA-Analyzer/2.0\r\nConnection: close\r\n\r\n",
    554:  b"OPTIONS rtsp://target:554/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: IDSA-Analyzer/2.0\r\n\r\n",
    8080: b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: IDSA-Analyzer/2.0\r\nConnection: close\r\n\r\n",
}


def grab_banner(host, port, timeout=1.5):
    """Connects to host:port, sends lightweight probe, extracts raw banner/header."""
    banner = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(s, server_hostname=host)
        else:
            sock = s

        sock.connect((host, port))

        probe = COMMON_PROBES.get(port, b"\r\n")
        if probe:
            sock.sendall(probe)

        data = sock.recv(2048)
        banner = data.decode("utf-8", errors="ignore").strip()
        sock.close()
    except Exception:
        pass
    return banner


def fingerprint_service(host, port):
    """
    Analyzes raw banner to determine precise service name, version, and web page title.
    Returns parsed dictionary.
    """
    raw_banner = grab_banner(host, port)
    info = {
        "port": port,
        "service": "Unknown",
        "banner": raw_banner[:160] if raw_banner else "",
        "title": "",
        "server_header": "",
        "auth_realm": "",
    }

    if not raw_banner:
        return info

    # Check for HTTP/HTTPS headers
    if "HTTP/" in raw_banner:
        info["service"] = "HTTP/Web"
        # Server header
        srv_match = re.search(r"Server:\s*([^\r\n]+)", raw_banner, re.IGNORECASE)
        if srv_match:
            info["server_header"] = srv_match.group(1).strip()
            info["service"] = f"Web ({info['server_header']})"

        # HTML Title
        title_match = re.search(r"<title>([^<]+)</title>", raw_banner, re.IGNORECASE)
        if title_match:
            info["title"] = title_match.group(1).strip()

        # Auth realm
        auth_match = re.search(r'WWW-Authenticate:\s*(?:Basic|Digest)\s+realm="([^"]+)"', raw_banner, re.IGNORECASE)
        if auth_match:
            info["auth_realm"] = auth_match.group(1).strip()

    elif "SSH-" in raw_banner:
        info["service"] = "SSH"
        info["server_header"] = raw_banner.splitlines()[0]

    elif "220" in raw_banner and any(k in raw_banner.lower() for k in ("ftp", "filezilla", "vsftpd", "pure-ftpd")):
        info["service"] = "FTP"
        info["server_header"] = raw_banner.splitlines()[0]

    elif "RTSP/" in raw_banner:
        info["service"] = "RTSP Video Stream (IP Camera)"
        srv_match = re.search(r"Server:\s*([^\r\n]+)", raw_banner, re.IGNORECASE)
        if srv_match:
            info["server_header"] = srv_match.group(1).strip()

    return info


def scan_host_fingerprints(host, open_ports):
    """Scans and fingerprints all discovered open ports on a given host."""
    fingerprints = []
    for port in open_ports:
        fp = fingerprint_service(host, port)
        fingerprints.append(fp)
    return fingerprints
