"""
scan_runner.py  -  CLI bridge between Node.js and IDSA Python scanner modules.
Integrates system, network, processes, persistence, account audit, USB, and CVE analysis.
"""

import sys
import os
import json
import argparse
import datetime
import uuid
import base64

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR   = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))   # IDSA_Existing/
PROJECT_ROOT = os.path.abspath(os.path.join(PARENT_DIR, ".."))   # project root

sys.path.insert(0, PARENT_DIR)

MOCK_USB_DIR = os.path.join(PROJECT_ROOT, "MOCK_USB", "IDSA_REPORTS")
os.makedirs(MOCK_USB_DIR, exist_ok=True)

def log(msg: str):
    print(f"[IDSA] {msg}", file=sys.stderr, flush=True)

def emit(data: dict):
    print(json.dumps(data, default=str), flush=True)

def _derive_risk(open_ports: list) -> str:
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
    cve_map = {
        21:   ["CVE-2015-3306", "CVE-2010-4221"],
        22:   ["CVE-2023-38408", "CVE-2016-10009"],
        23:   ["CVE-1999-0254"],
        80:   ["CVE-2021-41773", "CVE-2017-5638"],
        443:  ["CVE-2022-22719"],
        445:  ["CVE-2017-0144", "CVE-2017-0145"],
        3389: ["CVE-2019-0708", "CVE-2019-1181"],
        8080: ["CVE-2022-26134"],
    }
    cves = []
    for port in open_ports:
        cves.extend(cve_map.get(port, []))
    return list(dict.fromkeys(cves))

def _get_vendor_guess(mac: str) -> str:
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
    return "Unknown Vendor / Network Device"

def run_full_scan() -> dict:
    scan_id = "scan_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    devices = []
    vulnerabilities = []

    # 1. System info
    log("Collecting host OS & hardware information...")
    try:
        import system_scanner
        system_data = system_scanner.get_system_info_fast()
    except Exception as e:
        log(f"system_scanner error: {e}")
        system_data = {"error": str(e)}

    # 2. USB Devices
    log("Enumerating physical USB devices & controllers...")
    try:
        import usb_scanner
        usb_devices = usb_scanner.get_usb_devices()
    except Exception as e:
        log(f"usb_scanner error: {e}")
        usb_devices = []

    # 3. Active Process Scan (Advanced anti-malware check)
    log("Scanning running processes for suspicious activity & temp binaries...")
    try:
        import process_scanner
        proc_data = process_scanner.run_process_scan()
        vulnerabilities.extend(proc_data.get("findings", []))
    except Exception as e:
        log(f"process_scanner error: {e}")
        proc_data = {"error": str(e)}

    # 4. Persistence Mechanisms (Registry autoruns, Tasks, Startup)
    log("Checking persistence mechanisms (Autorun keys, Scheduled Tasks)...")
    try:
        import persistence_scanner
        persist_data = persistence_scanner.run_persistence_scan()
        vulnerabilities.extend(persist_data.get("registry_autoruns", []))
        vulnerabilities.extend(persist_data.get("startup_folder", []))
        vulnerabilities.extend(persist_data.get("scheduled_tasks", []))
    except Exception as e:
        log(f"persistence_scanner error: {e}")
        persist_data = {"error": str(e)}

    # 5. Local User Accounts & Password Policy
    log("Auditing local accounts, admin privileges and password requirements...")
    try:
        import user_account_scanner
        user_data = user_account_scanner.scan_user_accounts()
        vulnerabilities.extend(user_data.get("findings", []))
    except Exception as e:
        log(f"user_account_scanner error: {e}")
        user_data = {"error": str(e)}

    # 6. Deep Network Posture (Firewall, DNS tampering, ARP table, Open listeners)
    log("Analyzing network posture (Firewall profiles, DNS configuration, ARP table)...")
    try:
        import network_security_scanner
        net_sec = network_security_scanner.run_network_security_scan()
        vulnerabilities.extend(net_sec.get("findings", []))
    except Exception as e:
        log(f"network_security_scanner error: {e}")
        net_sec = {"error": str(e)}

    # 7. Network ping sweep + port scanner
    log("Running LAN discovery & port scan...")
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

    for host in active_hosts:
        open_ports = open_ports_map.get(host, [])
        if isinstance(open_ports, str):
            open_ports = []
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
                "severity":       risk,
                "module":         "Network Device",
                "description":    f"Host {host} exposes sensitive service ports: {open_ports}",
                "recommendation": f"Enforce firewall rules to block unsolicited inbound access to ports {open_ports} on host {host}."
            })

    # 8. Config Scanner
    log("Checking configuration issues and credentials...")
    try:
        import config_scanner
        raw_config_vulns = config_scanner.scan_configuration_issues(open_ports_map)
        config_vulns = []
        for v in raw_config_vulns:
            config_vulns.append({
                **v,
                "module": v.get("module", "Config Audit"),
                "recommendation": v.get("recommendation", "Review and change default credentials, disable unencrypted protocols.")
            })
    except Exception as e:
        log(f"config_scanner error: {e}")
        config_vulns = []

    vulnerabilities.extend(config_vulns)

    result = {
        "scan_id":               scan_id,
        "timestamp":             datetime.datetime.now().isoformat(),
        "local_ip":              local_ip,
        "network_range":         network_range,
        "devices":               devices,
        "system_info":           system_data,
        "usb_devices":           usb_devices,
        "process_summary":       proc_data.get("total_processes", 0) if isinstance(proc_data, dict) else 0,
        "user_accounts":         user_data.get("local_users", []) if isinstance(user_data, dict) else [],
        "config_issues_results": config_vulns,
        "vulnerabilities":       vulnerabilities,
    }
    return result

def run_generate_report(scan_data: dict | None = None) -> dict:
    if scan_data is None:
        scan_data = {
            "timestamp":       datetime.datetime.now().isoformat(),
            "devices":         [],
            "vulnerabilities": [],
        }

    log("Generating reports (JSON, HTML, genuine PDF) via ReportLab...")
    try:
        import report_generator
        original_base = report_generator.REPORT_BASE_DIR
        report_generator.REPORT_BASE_DIR = MOCK_USB_DIR

        rg = report_generator.ReportGenerator()
        report_info = rg.generate_report(scan_data, export_formats=("json", "html", "pdf"))

        report_generator.REPORT_BASE_DIR = original_base

        log(f"Report files generated successfully in {report_info['report_dir']}")
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

def main():
    parser = argparse.ArgumentParser(description="IDSA Scanner Engine Bridge")
    parser.add_argument("--scan",   action="store_true", help="Run full multi-layer scan and emit JSON")
    parser.add_argument("--report", action="store_true", help="Generate reports to USB drive")
    parser.add_argument("--scan-data", dest="scan_data", help="Base64-encoded JSON scan data")
    parser.add_argument("--scan-file", dest="scan_file", help="Path to JSON file containing scan results")
    args = parser.parse_args()

    if args.scan:
        result = run_full_scan()
        emit(result)
    elif args.report:
        scan_data = None
        if args.scan_file and os.path.exists(args.scan_file):
            try:
                with open(args.scan_file, "r", encoding="utf-8") as f:
                    scan_data = json.load(f)
            except Exception as e:
                log(f"Could not load scan_file {args.scan_file}: {e}")
        elif args.scan_data:
            try:
                raw = base64.b64decode(args.scan_data).decode("utf-8")
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
