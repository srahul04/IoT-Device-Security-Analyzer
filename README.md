# IoT Device Security Analyzer (IDSA)

A portable, web-based security audit and analysis suite designed for authorized assessment of IoT networks and host machines. Operates directly from removable USB media, provides interactive browser simulation, and exports comprehensive security reports.

**Author: Rahul S**

---

## Architecture Overview

The project is structured according to Clean Architecture principles with clear separation of concerns:

```
[ React 18 Web UI (Tailwind CSS) ]
                 |
            (HTTP/JSON)
                 |
[ Express.js REST API Layer ]
   |-- config/          (Environment, dynamic portable paths)
   |-- middleware/      (JWT verification, IP rate limiters, Helmet)
   |-- controllers/     (Request/response routing and validation)
   |-- services/        (Engine orchestration, report management)
   `-- routes/          (Modular API route table)
                 |
     (Process Interceptor)
                 |
[ Python Security Engine ]
   |-- runner/          (CLI bridge and dispatcher)
   |-- scanners/        (Modular threat and posture packages)
   |   |-- network_scanner.py          (Ping sweeps, port enumeration)
   |   |-- network_security_scanner.py (DNS integrity, ARP spoofing, Firewall)
   |   |-- process_scanner.py          (Suspicious binaries, temp execution)
   |   |-- persistence_scanner.py      (Run keys, Startup items, Tasks)
   |   |-- user_account_scanner.py     (Guest status, password policy)
   |   |-- config_scanner.py           (Credential and service audits)
   |   |-- system_scanner.py           (Host telemetry)
   |   `-- usb_scanner.py              (Attached peripherals)
   `-- report_generator.py             (ReportLab vector PDF, HTML, JSON)
                 |
                 v
[ Removable Media Storage: MOCK_USB/IDSA_REPORTS/<scan_id>/ ]
```

---

## Directory Structure

```
IoT Device Security Analyzer (IDSA)/
|-- backend/
|   |-- config/               Dynamic runtime and path configuration
|   |-- controllers/          API request handlers (auth, scan, system)
|   |-- middleware/           JWT token validation, rate-limiting
|   |-- routes/               API endpoint mapping
|   |-- services/             Python execution and report file services
|   |-- package.json
|   `-- server.js             Express application bootstrap
|
|-- frontend/
|   |-- build/                Compiled production bundle
|   |-- src/
|   |   |-- components/       ConsentModal, Dashboard, Results, DeviceCard
|   |   |-- App.jsx           State machine and consent flow
|   |   `-- index.css         Tailwind styles and cyber dark theme
|   `-- package.json
|
|-- IDSA_Existing/
|   |-- runner/
|   |   `-- scan_runner.py    Python execution orchestrator
|   |-- scanners/             Modular scanner package
|   |   |-- __init__.py
|   |   |-- network_scanner.py
|   |   |-- network_security_scanner.py
|   |   |-- persistence_scanner.py
|   |   |-- process_scanner.py
|   |   |-- user_account_scanner.py
|   |   |-- config_scanner.py
|   |   |-- system_scanner.py
|   |   `-- usb_scanner.py
|   |-- report_generator.py   ReportLab binary PDF generator
|   `-- requirements.txt
|
|-- assets/
|   `-- cve_database.json     Reference vulnerabilities database
|
|-- MOCK_USB/
|   `-- IDSA_REPORTS/         Report output destination (PDF, HTML, JSON)
|
|-- launch.bat                Windows portable launcher
|-- launch.ps1                PowerShell portable launcher
|-- .env.example              Template for local environment configuration
`-- README.md
```

---

## Scanners & Security Capabilities

IDSA goes beyond signature-based antivirus scanning by analyzing system posture, persistence mechanisms, and network integrity:

1. **Process Threat Analysis (`process_scanner.py`)**:
   - Detects executables launching out of temporary folders (`%TEMP%`, `%APPDATA%`).
   - Flags obfuscated command strings (e.g. encoded PowerShell `-enc` / `-w hidden`).
   - Checks against known attacker tooling (Mimikatz, netcat, cryptominers).

2. **Persistence Mechanism Inspection (`persistence_scanner.py`)**:
   - Audits Windows Registry Run keys (`HKLM` / `HKCU` `Software\Microsoft\Windows\CurrentVersion\Run`).
   - Audits the user's Startup folder.
   - Inspects active Scheduled Tasks for unauthorized non-system tasks.

3. **User Account & Password Policy Audit (`user_account_scanner.py`)**:
   - Checks if the built-in Guest account is active.
   - Flags user accounts configured with no password requirement.
   - Audits members of the local `Administrators` security group.
   - Validates minimum password length against policy requirements.

4. **Network Posture & Integrity (`network_security_scanner.py`)**:
   - **DNS Hijack Detection**: Detects rogue loopback or proxy resolvers.
   - **ARP Spoofing Detection**: Identifies duplicate MAC addresses mapped to multiple IPs.
   - **Firewall Audit**: Checks active state of Domain, Private, and Public profiles.
   - **Service-to-PID Mapping**: Links open TCP/UDP listening ports to owning process names and PIDs.

5. **IoT Network Discovery (`network_scanner.py`)**:
   - Concurrently sweeps subnets via fast ping sweeps.
   - Scans common IoT and administrative ports (21, 22, 23, 80, 443, 445, 3389, 8080).
   - Correlates open ports with known CVE vulnerabilities.

---

## Portable USB Usage

1. Copy the project root to your USB drive.
2. Ensure Python 3.10+ and Node.js 18+ are installed on the host (or place standalone runtimes in `tools/python/` and `tools/node/`).
3. Set your private secret in `.env` (refer to `.env.example`).
4. Double-click `launch.bat`.
5. The launcher starts the backend and opens your default browser at `http://localhost:5000`.
6. Review the legal notice and type `IAGREE` to authorize execution.
7. Click **Start Scan** to run the scan.
8. Click **Generate & Save Report** to write reports to `MOCK_USB/IDSA_REPORTS/<scan_id>/`.

---

## API Reference

| Method | Endpoint | Authorization | Description |
|---|---|---|---|
| `GET` | `/api/health` | None | Returns engine status, host name, and paths |
| `POST` | `/api/approve` | None | Validates `IAGREE` consent and issues JWT |
| `POST` | `/api/scan` | JWT Bearer | Triggers multi-vector scan and returns JSON |
| `POST` | `/api/generate-report`| JWT Bearer | Generates binary PDF, HTML, and JSON reports |
| `GET` | `/api/reports` | JWT Bearer | Lists all generated reports on the USB drive |
| `GET` | `/api/reports/:id/:file` | JWT Bearer | Downloads a specific report artifact |

---

## Legal Notice

This software is designed solely for educational purposes and authorized security evaluations on networks and systems where explicit permission has been granted. Unauthorized scanning is strictly prohibited under cybersecurity regulations. The author assumes no responsibility for unauthorized use.
