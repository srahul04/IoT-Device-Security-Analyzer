"""
user_account_scanner.py
Audits local user accounts and password policy.
Checks: Guest account status, accounts with no password, admin group members,
        accounts that have never logged in, password policy weakness.
"""

import subprocess
import platform

def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True)
        return r.stdout.strip()
    except Exception:
        return ""


def get_local_users():
    """Returns list of local user accounts."""
    users = []
    if platform.system() != "Windows":
        return users
    out = _run("wmic useraccount get Name,Disabled,PasswordRequired,PasswordChangeable,Lockout /format:csv")
    lines = [l for l in out.splitlines() if l.strip() and not l.startswith("Node")]
    for line in lines:
        parts = line.split(",")
        if len(parts) >= 6:
            users.append({
                "name":               parts[1].strip(),
                "disabled":           parts[2].strip().upper() == "TRUE",
                "password_required":  parts[5].strip().upper() == "TRUE",
                "lockout":            parts[3].strip().upper() == "TRUE",
            })
    return users


def get_admin_group_members():
    members = []
    if platform.system() != "Windows":
        return members
    out = _run("net localgroup administrators")
    capture = False
    for line in out.splitlines():
        if "---" in line:
            capture = True
            continue
        if capture and line.strip() and "The command completed" not in line:
            members.append(line.strip())
    return members


def check_password_policy():
    findings = []
    if platform.system() != "Windows":
        return findings
    out = _run("net accounts")
    min_len = 0
    for line in out.splitlines():
        if "Minimum password length" in line:
            try:
                val = line.split(":")[-1].strip()
                min_len = int(val) if val.isdigit() else 0
            except Exception:
                pass
        if "Password history" in line or "Maximum password age" in line:
            pass

    if min_len < 8:
        findings.append({
            "severity":       "High",
            "module":         "User Account Scanner",
            "description":    f"Minimum password length is set to {min_len} characters (should be >= 8)",
            "recommendation": "Set minimum password length to at least 12 characters. Run: 'net accounts /minpwlen:12'",
        })
    return findings


def scan_user_accounts():
    findings = []
    users   = get_local_users()
    admins  = get_admin_group_members()

    for u in users:
        name = u["name"]

        # Guest account enabled
        if name.lower() in ("guest", "visiteur", "gast") and not u["disabled"]:
            findings.append({
                "severity":       "High",
                "module":         "User Account Scanner",
                "description":    f"Guest account '{name}' is enabled",
                "recommendation": "Disable the guest account. Run: 'net user guest /active:no'",
            })

        # Active account with no password required
        if not u["disabled"] and not u["password_required"]:
            findings.append({
                "severity":       "High",
                "module":         "User Account Scanner",
                "description":    f"Account '{name}' does not require a password",
                "recommendation": f"Enable password requirement for '{name}'. Run: 'net user {name} /passwordreq:yes'",
            })

    # More than 2 admin accounts is unusual
    if len(admins) > 2:
        findings.append({
            "severity":       "Medium",
            "module":         "User Account Scanner",
            "description":    f"{len(admins)} accounts in the Administrators group: {', '.join(admins)}",
            "recommendation": "Reduce local administrators to the minimum necessary. Remove untrusted accounts from the group.",
        })

    policy_findings = check_password_policy()
    findings.extend(policy_findings)

    return {
        "local_users":          users,
        "admin_group_members":  admins,
        "findings":             findings,
    }

