# IoT Device Security Analyzer (IDSA)

A portable, web-based security scanner for IoT networks. Plug the tool into a USB drive, run `launch.bat` on any Windows machine, and get a full security report saved back to the drive.

**Author: Rahul S**

---

![Dashboard](Screenshots/Final.png)

---

## How it works

The tool has three layers:

1. **Python scanner** (`IDSA_Existing/`) - performs network discovery, port scanning, CVE mapping, system inspection, and USB enumeration.
2. **Node.js backend** (`backend/`) - Express API that receives requests from the UI, spawns the Python scanner, and saves reports to the USB drive.
3. **React frontend** (`frontend/`) - dark-themed web UI served by the backend. Opens in the user's browser automatically.

```
React UI  <-->  Node/Express API  <-->  Python Scanners  -->  MOCK_USB/IDSA_REPORTS/
```

---

## Project Structure

```
IoT Device Security Analyzer (IDSA)/
|
+-- IDSA_Existing/              Python scanner modules
|   +-- runner/
|   |   +-- scan_runner.py      CLI bridge between Node and Python
|   +-- main.py
|   +-- network_scanner.py
|   +-- system_scanner.py
|   +-- usb_scanner.py
|   +-- cve_scanner.py
|   +-- config_scanner.py
|   +-- report_generator.py
|   +-- requirements.txt
|
+-- assets/
|   +-- cve_database.json       Local CVE reference database
|
+-- backend/                    Node.js Express API
|   +-- server.js
|   +-- package.json
|
+-- frontend/                   React + Tailwind UI
|   +-- src/
|   |   +-- App.jsx
|   |   +-- components/
|   |       +-- ConsentModal.jsx
|   |       +-- Dashboard.jsx
|   |       +-- Results.jsx
|   |       +-- DeviceCard.jsx
|   |       +-- Header.jsx
|   |       +-- Footer.jsx
|   +-- public/
|   +-- package.json
|
+-- MOCK_USB/
|   +-- IDSA_REPORTS/           Reports are saved here (simulates USB storage)
|
+-- docs/
|   +-- screenshots/            UI screenshots
|
+-- Screenshots/                Reference screenshots for README
+-- launch.bat                  Windows launcher (portable)
+-- launch.ps1                  PowerShell launcher (portable)
+-- .env                        Environment variables (JWT secret, port) - not committed
+-- .env.example                Template for .env
+-- README.md
```

---

## Portable USB Setup

This tool is designed to run from a USB drive without being installed on the target machine. The only prerequisites on the target machine are **Python 3.10+** and **Node.js 18+**.

If you want a fully self-contained drive (no install needed), place portable builds of Python and Node inside `tools/python/` and `tools/node/` on the drive. The launcher will detect and use them automatically.

### Steps

1. Copy the entire project folder to your USB drive.
2. Set a secure JWT secret in `.env` (copy from `.env.example` and fill in the secret).
3. Install dependencies once on a trusted machine:
   ```
   cd backend && npm install
   cd ../frontend && npm install && npm run build
   ```
4. Plug the USB into the target machine and double-click `launch.bat`.
5. The browser opens at `http://localhost:5000`.
6. Type `IAGREE` in the authorization modal.
7. Click **Start Scan**.
8. Click **Download Report** when the scan completes.
9. Reports are saved to `MOCK_USB/IDSA_REPORTS/<scan-id>/` on the USB.

---

## Development Setup

### Prerequisites

- Python 3.10 or later
- Node.js 18 or later and npm

### 1. Install Python dependencies

```bash
cd IDSA_Existing
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### 2. Install Node dependencies

```bash
cd backend && npm install
cd ../frontend && npm install
```

### 3. Set up environment

```bash
copy .env.example .env
```

Open `.env` and set a strong random value for `JWT_SECRET`. Generate one with:

```powershell
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$b = New-Object byte[] 32; $rng.GetBytes($b)
[Convert]::ToBase64String($b)
```

### 4. Run in development mode

Terminal 1 - backend:
```bash
cd backend
npm start
```

Terminal 2 - frontend (hot reload):
```bash
cd frontend
npm start
```

Open `http://localhost:3000` in your browser.

### 5. Run in production mode

```bash
cd frontend && npm run build
cd ../backend && npm start
```

Open `http://localhost:5000`.

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/approve` | None | Accepts `IAGREE`, returns a JWT token |
| POST | `/api/scan` | JWT | Runs the full scan, returns JSON results |
| POST | `/api/generate-report` | JWT | Generates report files, saves to MOCK_USB |
| GET | `/api/reports` | JWT | Lists saved report folders |
| GET | `/api/reports/:id/:file` | JWT | Downloads a report file |
| GET | `/api/health` | None | Health check |

---

## Security Design

- Every API call except `/api/approve` and `/api/health` requires a JWT token.
- The token is issued only after the user types `IAGREE` on the UI (physical approval requirement).
- The JWT is stored in `sessionStorage` and expires after 8 hours.
- The backend uses `helmet` for secure HTTP headers and `express-rate-limit` to prevent abuse.
- Path traversal is prevented on the report download endpoint by using `path.basename()`.
- The JWT secret lives in `.env` on the USB drive and is never committed to version control.

---

## Features

- Authorization gate requiring physical user approval
- Network device discovery with ping sweep and port scanning
- CVE mapping for detected open ports
- System information collection (OS, hardware)
- USB device enumeration
- Configuration issue detection
- HTML and JSON reports saved to USB storage
- Dark-themed web UI with real-time scan progress

---

## Legal Notice

This tool is for authorized security testing and educational use only. You must have explicit written permission to scan any network or device you do not own. The author assumes no liability for misuse or any damage caused by this software.

---

## Screenshots

| Consent Gate | Dashboard | Scan Results |
|---|---|---|
| ![](Screenshots/1.png) | ![](Screenshots/Final.png) | ![](Screenshots/IDSA_Report.png) |
