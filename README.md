# IoT Device Security Analyzer (IDSA)

A portable, web-based cybersecurity audit and analysis suite designed for authorized penetration testing, vulnerability assessment, and security posture evaluation of IoT networks and host machines. Operates directly from removable USB media, provides interactive browser simulation, and exports comprehensive security reports.

**Author: Rahul S**

---

## Architecture Overview

The project is structured according to Clean Architecture principles with clear separation of concerns across presentation, application routing, business services, and scanning engine layers:

```
[ React 18 Web UI (Tailwind CSS Dark Cybersecurity Theme) ]
                              |
                         (HTTP/JSON)
                              |
[ Express.js REST API Layer (backend/) ]
   |-- config/          (Environment, dynamic portable paths)
   |-- middleware/      (JWT verification, IP rate limiters, Helmet)
   |-- controllers/     (Request/response routing and validation)
   |-- services/        (Python engine execution, report file management)
   `-- routes/          (Modular API route table)
                              |
               (Process Interceptor Bridge)
                              |
[ Python 3 Security Engine (IDSA_Existing/) ]
   |-- runner/          (CLI bridge and multi-layer scanner dispatcher)
   |-- scanners/        (Modular security audit & threat packages)
   |   |-- iot_discovery.py            (SSDP / UPnP broadcast discovery)
   |   |-- banner_grabber.py           (HTTP headers, titles, RTSP fingerprints)
   |   |-- iot_protocols.py            (MQTT anonymous brokers, RTSP streams)
   |   |-- credential_auditor.py       (Safe default IoT credential testing)
   |   |-- network_scanner.py          (Concurrent ping sweeps & port audits)
   |   |-- network_security_scanner.py (DNS integrity, ARP spoofing, Firewall)
   |   |-- process_scanner.py          (Suspicious binaries, temp execution)
   |   |-- persistence_scanner.py      (Run keys, Startup items, Tasks)
   |   |-- user_account_scanner.py     (Guest status, password policies)
   |   |-- config_scanner.py           (Weak credential and service checks)
   |   |-- system_scanner.py           (Host OS & hardware telemetry)
   |   `-- usb_scanner.py              (USB controllers & attached peripherals)
   `-- report_generator.py             (Binary ReportLab vector PDF, HTML, JSON)
                              |
                              v
[ Removable Media Output: MOCK_USB/IDSA_REPORTS/<scan_id>/ ]
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
|   |   |-- iot_discovery.py            SSDP/UPnP broadcast discovery
|   |   |-- banner_grabber.py           Service banner & web title grabber
|   |   |-- iot_protocols.py            MQTT & RTSP stream auditor
|   |   |-- credential_auditor.py       Factory default credential auditor
|   |   |-- network_scanner.py          LAN ping sweep & port scan
|   |   |-- network_security_scanner.py DNS, ARP spoofing, Firewall
|   |   |-- persistence_scanner.py      Run keys, Startup folder, Tasks
|   |   |-- process_scanner.py          Process threat scanner
|   |   |-- user_account_scanner.py     Guest accounts, password policy
|   |   |-- config_scanner.py           Service configuration checks
|   |   |-- system_scanner.py           Host OS & hardware telemetry
|   |   `-- usb_scanner.py              USB hardware bus enumerator
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

## Comprehensive Security Audit Capabilities

IDSA goes far beyond signature-based antivirus scanning by analyzing system posture, persistence mechanisms, network integrity, and IoT-specific attack surfaces:

1. **Active IoT Broadcast Discovery (`iot_discovery.py`)**:
   - Sends `M-SEARCH * HTTP/1.1` UDP multicasts (`239.255.255.250:1900`) to discover UPnP devices (Smart TVs, Cameras, Printers, Routers, Smart Speakers).
   - Retrieves XML descriptors to identify friendly names, manufacturers, model names, and model numbers.

2. **Banner Grabbing & Service Fingerprinting (`banner_grabber.py`)**:
   - Sends protocol-specific probes across open ports (HTTP, HTTPS, SSH, FTP, Telnet, RTSP).
   - Extracts HTML `<title>` tags, `Server:` headers, and `WWW-Authenticate` realms.

3. **Specialized IoT Protocol Audit (`iot_protocols.py`)**:
   - **MQTT Broker Inspection (Port 1883)**: Sends a standard MQTT 3.1.1 CONNECT packet without credentials. Flags anonymous broker access exposing real-time sensor telemetry.
   - **RTSP Camera Streams (Port 554)**: Probes video stream endpoints with unauthenticated `DESCRIBE` requests to detect exposed IP camera feeds.

4. **Safe Default Credential Audit (`credential_auditor.py`)**:
   - Safely audits web management portals against common factory credentials (`admin:admin`, `admin:password`, `admin:1234`, `root:root`).
   - Flags critical exposures that enable automated Mirai botnet propagation.

5. **Host Persistence Mechanism Inspection (`persistence_scanner.py`)**:
   - Audits Windows Registry Run keys (`HKLM` / `HKCU` `Software\Microsoft\Windows\CurrentVersion\Run`).
   - Audits the user's Startup folder.
   - Inspects active Scheduled Tasks for unauthorized non-system tasks surviving reboots.

6. **Process Threat Analysis (`process_scanner.py`)**:
   - Detects executables launching out of temporary folders (`%TEMP%`, `%APPDATA%`).
   - Flags obfuscated command strings (e.g. encoded PowerShell `-enc` / `-w hidden`).
   - Checks against known attacker tooling (Mimikatz, netcat, cryptominers).

7. **User Account & Password Policy Audit (`user_account_scanner.py`)**:
   - Flags enabled Guest accounts.
   - Identifies accounts with no password requirement.
   - Audits members of the local `Administrators` security group.
   - Validates minimum password length against policy requirements.

8. **Network Posture & Integrity (`network_security_scanner.py`)**:
   - **DNS Hijack Detection**: Detects rogue loopback or proxy resolvers.
   - **ARP Spoofing Detection**: Identifies duplicate MAC addresses mapped to multiple IPs.
   - **Firewall Audit**: Checks active state of Domain, Private, and Public profiles.
   - **Service-to-PID Mapping**: Links open TCP/UDP listening ports to owning process names and PIDs.

9. **Actionable Remediation Guidance**:
   - Every detected issue pairs an assessed risk level with an actionable recommendation (firewall rules, password policy enforcement, service restrictions, and registry cleanup).

---

## Portable USB Usage

1. Copy the project root to your USB drive.
2. Ensure Python 3.10+ and Node.js 18+ are available on the host (or place standalone runtimes in `tools/python/` and `tools/node/`).
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
