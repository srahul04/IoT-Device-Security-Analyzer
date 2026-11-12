"""
persistence_scanner.py
Detects persistence mechanisms installed on the host.
Checks: Windows Startup registry keys, Scheduled Tasks, Startup folder entries,
        services set to auto-start from unusual locations.
These are the most common techniques used by malware to survive reboots.
"""

import os
import subprocess
import platform

def _run(cmd, shell=True):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15, shell=shell)
        return r.stdout.strip()
    except Exception:
        return ""


def _winreg_read(hive, key):
    """Read all values under a registry key. Returns list of (name, data) tuples."""
    entries = []
    try:
        import winreg
        with winreg.OpenKey(hive, key, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(k, i)
                    entries.append((name, str(data)))
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    return entries


AUTORUN_KEYS = [
    (None, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (None, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (None, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

SUSPICIOUS_AUTORUN_PATHS = [
    os.environ.get("TEMP", "").lower(),
    os.environ.get("TMP", "").lower(),
    "appdata\\local\\temp",
    "\\public\\",
    "\\downloads\\",
]


def scan_registry_autoruns():
    findings = []
    if platform.system() != "Windows":
        return findings
    try:
        import winreg
        hives = [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
            (winreg.HKEY_CURRENT_USER,  "HKCU"),
        ]
        for hive, hive_name in hives:
            for _, key in AUTORUN_KEYS:
                for name, data in _winreg_read(hive, key):
                    finding = {
                        "location": f"{hive_name}\\{key}",
                        "entry":    name,
                        "command":  data,
                    }
                    data_low = data.lower()
                    suspicious = any(p for p in SUSPICIOUS_AUTORUN_PATHS if p and p in data_low)
                    if suspicious:
                        findings.append({
                            "severity":       "High",
                            "module":         "Persistence Scanner",
                            "description":    f"Autorun entry pointing to suspicious path: [{name}] = {data}",
                            "recommendation": "Remove this autorun entry if it is not from a known trusted application. Run 'regedit' and navigate to the key to delete it.",
                            "detail":         finding,
                        })
                    else:
                        findings.append({
                            "severity":       "Informational",
                            "module":         "Persistence Scanner",
                            "description":    f"Autorun entry found: [{name}] = {data[:80]}",
                            "recommendation": "Review this startup entry. If you do not recognise it, research the binary before trusting it.",
                            "detail":         finding,
                        })
    except ImportError:
        pass
    return findings


def scan_startup_folder():
    findings = []
    if platform.system() != "Windows":
        return findings
    startup_dirs = [
        os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    ]
    for d in startup_dirs:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            full = os.path.join(d, f)
            findings.append({
                "severity":       "Informational",
                "module":         "Persistence Scanner",
                "description":    f"Startup folder entry: {f} in {d}",
                "recommendation": "Verify this shortcut/script is from a trusted application.",
                "detail":         {"path": full},
            })
    return findings


def scan_scheduled_tasks():
    findings = []
    if platform.system() != "Windows":
        return findings
    out = _run("schtasks /query /fo CSV /NH 2>nul")
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) < 3:
            continue
        name, next_run, status = parts[0], parts[1], parts[2]
        if name.startswith("\\Microsoft"):
            continue   # skip built-in Windows tasks
        findings.append({
            "severity":       "Informational",
            "module":         "Persistence Scanner",
            "description":    f"Scheduled task: {name} (Status: {status})",
            "recommendation": "Verify this scheduled task. Unknown tasks that run at logon or startup are a common persistence method.",
            "detail":         {"name": name, "next_run": next_run, "status": status},
        })
    return findings


def run_persistence_scan():
    return {
        "registry_autoruns":   scan_registry_autoruns(),
        "startup_folder":      scan_startup_folder(),
        "scheduled_tasks":     scan_scheduled_tasks(),
    }

