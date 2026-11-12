"""
credential_auditor.py
Safe, non-destructive default credential audit against discovered IoT HTTP/web portals.
Tests a minimal, targeted list of common factory default credentials:
(admin:admin, admin:password, admin:1234, admin:12345, root:root).
"""

import urllib.request
import urllib.error
import base64

COMMON_IOT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
]


def test_http_basic_auth(host, port=80, timeout=1.8):
    """
    Tests whether an HTTP portal accepts common default credentials via Basic Auth.
    Halts immediately upon the first successful match. Non-destructive.
    """
    protocol = "https" if port in (443, 8443) else "http"
    url = f"{protocol}://{host}:{port}/"

    # First check if the page actually requires authentication
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IDSA-Security-Auditor/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # 200 without auth - page is unauthenticated
            return None
    except urllib.error.HTTPError as e:
        if e.code != 401:
            return None
    except Exception:
        return None

    # Host returned 401 Unauthorized, test default credentials safely
    for user, pwd in COMMON_IOT_CREDS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "IDSA-Security-Auditor/2.0"})
            token = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
            req.add_header("Authorization", f"Basic {token}")

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status in (200, 301, 302):
                    return {
                        "user": user,
                        "password": pwd,
                        "port": port,
                        "url": url
                    }
        except urllib.error.HTTPError as e:
            if e.code == 401:
                continue
        except Exception:
            pass

    return None


def run_credential_audit(active_hosts, open_ports_map):
    """Audits discovered hosts for default factory web credentials."""
    findings = []
    web_ports = [80, 8080, 443, 8443]

    for host in active_hosts:
        ports = open_ports_map.get(host, [])
        if isinstance(ports, str):
            continue

        for p in web_ports:
            if p in ports:
                match = test_http_basic_auth(host, p)
                if match:
                    findings.append({
                        "severity": "Critical",
                        "module": "Credential Auditor",
                        "description": f"Default IoT factory credentials active on {host}:{p} ({match['user']}:{match['password']})",
                        "recommendation": f"Change the default password for the '{match['user']}' account immediately. Default credentials are the primary entry point for Mirai and botnet variants."
                    })
                    break  # Stop checking additional ports for this host
    return findings
