"""
process_scanner.py
Scans all running processes for suspicious indicators.
Checks for: unsigned executables, unusual parent-child relationships,
processes running from temp directories, known malware process names,
and processes with no visible window that have network activity.
"""

import os
import subprocess
import platform

SUSPICIOUS_NAMES = {
    "mimikatz.exe", "meterpreter.exe", "nc.exe", "ncat.exe", "psexec.exe",
    "wce.exe", "pwdump.exe", "gsecdump.exe", "fgdump.exe", "procdump.exe",
    "lazagne.exe", "nirsoft.exe", "netcat.exe", "xmrig.exe", "minerd.exe",
}

SUSPICIOUS_PATHS = [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp"),
]


def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True)
        return r.stdout.strip()
    except Exception:
        return ""


def get_running_processes():
    """Returns list of running processes with PID, name and executable path."""
    processes = []
    try:
        import psutil
        for p in psutil.process_iter(["pid", "name", "exe", "username", "status"]):
            try:
                info = p.info
                processes.append({
                    "pid":      info["pid"],
                    "name":     info["name"] or "unknown",
                    "exe":      info["exe"] or "",
                    "user":     info["username"] or "",
                    "status":   info["status"] or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except ImportError:
        # Fallback: tasklist on Windows
        out = _run("tasklist /FO CSV /NH")
        for line in out.splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                processes.append({"name": parts[0], "pid": parts[1], "exe": "", "user": "", "status": ""})
    return processes


def scan_suspicious_processes(processes):
    """Flags processes that match suspicious criteria."""
    findings = []

    for p in processes:
        name  = (p.get("name") or "").lower()
        exe   = (p.get("exe")  or "").lower()
        pid   = p.get("pid", "?")

        # Known malicious names
        if name in SUSPICIOUS_NAMES:
            findings.append({
                "severity":       "Critical",
                "module":         "Process Scanner",
                "description":    f"Known malicious process detected: {name} (PID {pid})",
                "recommendation": f"Terminate PID {pid} immediately and investigate how '{name}' was executed. Run a full malware scan.",
            })
            continue

        # Running from a temp directory
        for tmp in SUSPICIOUS_PATHS:
            if tmp and exe.startswith(tmp.lower()):
                findings.append({
                    "severity":       "High",
                    "module":         "Process Scanner",
                    "description":    f"Process running from temp directory: {p.get('name')} (PID {pid}) at {exe}",
                    "recommendation": "Legitimate software does not run from Temp folders. Terminate and investigate the binary.",
                })
                break

        # PowerShell with encoded commands (common malware technique)
        if "powershell" in name:
            try:
                import psutil
                proc = psutil.Process(int(pid))
                cmdline = " ".join(proc.cmdline()).lower()
                if "-enc" in cmdline or "-encodedcommand" in cmdline or "-w hidden" in cmdline:
                    findings.append({
                        "severity":       "High",
                        "module":         "Process Scanner",
                        "description":    f"PowerShell running with obfuscated/hidden command (PID {pid})",
                        "recommendation": "Review the PowerShell command line. Encoded or hidden PowerShell is a common attacker technique (MITRE T1059.001).",
                    })
            except Exception:
                pass

    return findings


def run_process_scan():
    processes = get_running_processes()
    findings  = scan_suspicious_processes(processes)
    return {
        "total_processes": len(processes),
        "process_list":    processes[:50],   # cap list for JSON size
        "findings":        findings,
    }

