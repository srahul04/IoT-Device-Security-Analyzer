"""
scan_runner.py  –  CLI bridge between Node.js and the existing IDSA Python modules.

Usage:
    python scan_runner.py --scan          → runs the full scan, prints JSON to stdout
    python scan_runner.py --report        → generates HTML/JSON/PDF reports,
                                           saves them to MOCK_USB/IDSA_REPORTS/,
                                           prints report meta as JSON to stdout
    python scan_runner.py --report --scan-data <base64-json>
                                          → generates report from provided scan data

The script ONLY prints one thing to stdout: a single JSON object.
All log / progress messages go to stderr so Node.js can separate them cleanly.
"""

import sys
import os
import json
import argparse
import datetime
import uuid
import base64

# ── Make sure parent directory (IDSA_Existing) is importable ──────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR   = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))   # IDSA_Existing/
PROJECT_ROOT = os.path.abspath(os.path.join(PARENT_DIR, ".."))   # project root

sys.path.insert(0, PARENT_DIR)

# ── Mock-USB output directory (simulates saving to a USB drive) ───────────────
MOCK_USB_DIR = os.path.join(PROJECT_ROOT, "MOCK_USB", "IDSA_REPORTS")
os.makedirs(MOCK_USB_DIR, exist_ok=True)

# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg: str):
    """Write a progress line to stderr so Node.js can optionally stream it."""
    print(f"[IDSA] {msg}", file=sys.stderr, flush=True)


def emit(data: dict):
    """Write the final JSON result to stdout and exit cleanly."""
    print(json.dumps(data, default=str), flush=True)


# ── CVE / risk helpers (lightweight, no external API needed for demo) ─────────

def _derive_risk(open_ports: list) -> str:
    """Very simple heuristic: more sensitive ports → higher risk."""
    high_risk_ports  = {21, 22, 23, 3389, 445, 139}
    med_risk_ports   = {80, 8080, 8443, 25, 110, 143}
    if any(p in high_risk_ports for p in open_ports):
        return "High"
    if any(p in med_risk_ports for p in open_ports):
        return "Medium"
    if open_ports:
        return "Low"
    return "Informational"


def _mock_cves_for_ports(open_ports: list) -> list:
    """Return plausible CVE IDs based on well-known port exposures."""
    cve_map = {
        21:   ["CVE-2015-3306", "CVE-2010-4221"],   # FTP
        22:   ["CVE-2023-38408", "CVE-2016-10009"], # SSH / OpenSSH
        23:   ["CVE-1999-0254"],                     # Telnet
        80:   ["CVE-2021-41773", "CVE-2017-5638"],  # HTTP
        443:  ["CVE-2022-22719"],                    # HTTPS/TLS
        445:  ["CVE-2017-0144", "CVE-2017-0145"],   # EternalBlue / SMB
        3389: ["CVE-2019-0708", "CVE-2019-1181"],   # BlueKeep / RDP
        8080: ["CVE-2022-26134"],                    # Alt HTTP
    }
    cves = []
    for port in open_ports:
        cves.extend(cve_map.get(port, []))
    return list(dict.fromkeys(cves))  # deduplicate, preserve order


def _get_vendor_guess(mac: str) -> str:
    """Very small OUI prefix table for demo purposes."""
    oui_table = {
        "AA:BB": "Generic IP Camera",
        "00:50:56": "VMware vNIC",
        "08:00:27": "VirtualBox vNIC",
        "FC:EC:DA": "Ubiquiti Networks",
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Trading",
        "00:17:88": "Philips Hue / Signify",
    }
    mac_upper = mac.upper()
    for prefix, vendor in oui_table.items():
        if mac_upper.startswith(prefix):
            return vendor
    return "Unknown Vendor"


# ── Scan module ───────────────────────────────────────────────────────────────

def run_full_scan() -> dict:
    """
    Orchestrates the full scan by calling the existing IDSA Python modules.
    Returns a dict that is serialised to stdout as JSON.
    """
    scan_id = "scan_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    devices = []
    vulnerabilities = []

    # ── 1. System information ─────────────────────────────────────────────────
    log("Collecting system information …")
    try:
        import system_scanner
        system_data = system_scanner.get_system_info_fast()
    except Exception as e:
        log(f"system_scanner error: {e}")
        system_data = {"error": str(e)}

    # ── 2. USB devices ────────────────────────────────────────────────────────
    log("Enumerating USB devices …")
    try:
        import usb_scanner
        usb_devices = usb_scanner.get_usb_devices()
    except Exception as e:
        log(f"usb_scanner error: {e}")
        usb_devices = []

    # ── 3. Network scan ───────────────────────────────────────────────────────
    log("Running network discovery (ping sweep + port scan) …")
    try:
        import network_scanner
        net_result = network_scanner.fast_network_scan()
        local_ip   = network_scanner.get_local_ip()
        active_hosts    = net_result.get("active_hosts", [])
        open_ports_map  = net_result.get("scan_results", {})
        network_range   = net_result.get("network_range", "unknown")
    except Exception as e:
        log(f"network_scanner error: {e}")
        local_ip       = "127.0.0.1"
        active_hosts   = []
        open_ports_map = {}
        network_range  = "error"

    # ── 4. Build device cards (network devices) ───────────────────────────────
    log(f"Found {len(active_hosts)} active host(s). Building device cards …")
    for host in active_hosts:
        open_ports = open_ports_map.get(host, [])
        if isinstance(open_ports, str):          # error string
            open_ports = []
        # generate a deterministic-looking MAC for demo (real arp would be needed)
        mac_seed = sum(int(x) for x in host.split(".") if x.isdigit())
        mac = ":".join(f"{(mac_seed + i * 37) % 256:02X}" for i in range(6))
        risk   = _derive_risk(open_ports)
        cves   = _mock_cves_for_ports(open_ports)
        vendor = _get_vendor_guess(mac)

        device_card = {
            "ip":         host,
            "mac":        mac,
            "vendor":     vendor,
            "open_ports": open_ports,
            "risk_score": risk,
            "cves":       cves,
        }
        devices.append(device_card)

        if risk in ("High", "Critical"):
            vulnerabilities.append({
                "severity":    risk,
                "module":      "Network Scan",
                "description": f"Host {host} has risky open ports: {open_ports}",
            })

    # ── 5. Config issues ──────────────────────────────────────────────────────
    log("Checking configuration issues …")
    try:
        import config_scanner
        raw_config_vulns = config_scanner.scan_configuration_issues(open_ports_map)
        # Normalise: ensure every entry has a 'module' key for the React UI
        config_vulns = [
            {**v, "module": v.get("module", "Config Scan")}
            for v in raw_config_vulns
        ]
    except Exception as e:
        log(f"config_scanner error: {e}")
        config_vulns = []

    vulnerabilities.extend(config_vulns)

    # ── 6. CVE lookup for each discovered host ────────────────────────────────
    log("Running CVE lookups …")
    try:
        import cve_scanner
        # Use a generic IoT firmware keyword for demo
        cve_results = cve_scanner.search_cve("IoT firmware", None)
    except Exception as e:
        log(f"cve_scanner error: {e}")
        cve_results = []

    # ── Assemble the final JSON payload ───────────────────────────────────────
    result = {
        "scan_id":       scan_id,
        "timestamp":     datetime.datetime.now().isoformat(),
        "local_ip":      local_ip,
        "network_range": network_range,
        "devices":       devices,
        "system_info":   system_data,
        "usb_devices":   usb_devices,
        "cve_lookup_results":    cve_results,
        "config_issues_results": config_vulns,
        "vulnerabilities":       vulnerabilities,
    }
    return result


# ── Report module ─────────────────────────────────────────────────────────────

def run_generate_report(scan_data: dict | None = None) -> dict:
    """
    Calls the existing ReportGenerator and saves output to MOCK_USB_DIR.
    Returns a dict with report metadata.
    """
    if scan_data is None:
        # Minimal placeholder data so the generator has something to work with
        scan_data = {
            "timestamp":     datetime.datetime.now().isoformat(),
            "system_info":   {},
            "usb_devices":   [],
            "network_scan":  {},
            "cve_lookup_results":    [],
            "config_issues_results": [],
            "vulnerabilities": [],
        }

    log("Generating reports (JSON, HTML, PDF) …")
    try:
        import report_generator
        # Temporarily monkey-patch the base dir to point at MOCK_USB
        original_base = report_generator.REPORT_BASE_DIR
        report_generator.REPORT_BASE_DIR = MOCK_USB_DIR

        rg = report_generator.ReportGenerator()
        report_info = rg.generate_report(scan_data, export_formats=("json", "html", "pdf"))

        report_generator.REPORT_BASE_DIR = original_base  # restore

        log(f"Report saved → {report_info['report_dir']}")
        return {
            "status":     "success",
            "scan_id":    report_info["scan_id"],
            "report_dir": report_info["report_dir"],
            "files":      report_info["files"],
            "mock_usb":   MOCK_USB_DIR,
        }
    except Exception as e:
        log(f"report_generator error: {e}")
        return {"status": "error", "error": str(e)}


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IDSA CLI runner (Node.js bridge)")
    parser.add_argument("--scan",   action="store_true", help="Run full scan and emit JSON")
    parser.add_argument("--report", action="store_true", help="Generate reports, save to MOCK_USB")
    parser.add_argument("--scan-data", dest="scan_data",
                        help="Base64-encoded JSON scan data to use for --report")
    args = parser.parse_args()

    if args.scan:
        log("Starting IDSA full scan …")
        result = run_full_scan()
        emit(result)

    elif args.report:
        scan_data = None
        if args.scan_data:
            try:
                raw   = base64.b64decode(args.scan_data).decode("utf-8")
                scan_data = json.loads(raw)
            except Exception as e:
                log(f"Could not decode --scan-data: {e}")
        result = run_generate_report(scan_data)
        emit(result)

    else:
        parser.print_help(sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

