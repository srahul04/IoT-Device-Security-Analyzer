/**
 * server.js  –  IDSA Express Backend
 *
 * Routes:
 *   POST /api/scan            → spawns scan_runner.py --scan, streams JSON back
 *   POST /api/generate-report → spawns scan_runner.py --report, saves to MOCK_USB
 *   GET  /api/reports         → list files inside MOCK_USB/IDSA_REPORTS/
 *   GET  /api/reports/:id/:file → download a specific report file
 *
 * Start:  node server.js
 */

const express  = require("express");
const cors     = require("cors");
const path     = require("path");
const fs       = require("fs");
const { spawn } = require("child_process");

// ── Config ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;

// Absolute paths – adjust if your folder layout changes
const PROJECT_ROOT = path.resolve(__dirname, "..");
const PYTHON_RUNNER = path.join(
  PROJECT_ROOT,
  "IDSA_Existing",
  "runner",
  "scan_runner.py"
);
// Python inside the venv (Windows path); falls back to system python
const VENV_PYTHON = path.join(
  PROJECT_ROOT,
  "IDSA_Existing",
  ".venv",
  "Scripts",
  "python.exe"
);
const PYTHON_BIN = fs.existsSync(VENV_PYTHON) ? VENV_PYTHON : "python";

// Mock-USB folder (simulates an external USB drive)
const MOCK_USB_DIR = path.join(PROJECT_ROOT, "MOCK_USB", "IDSA_REPORTS");
fs.mkdirSync(MOCK_USB_DIR, { recursive: true });

// ── App setup ─────────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());

// ── Utility: run a Python command and collect stdout ─────────────────────────
/**
 * spawnPython(args)
 *
 * Spawns  `python scan_runner.py ...args`
 * Returns a Promise that resolves with the parsed JSON object from stdout.
 * stderr lines are forwarded to Node's console so you can watch progress.
 */
function spawnPython(args, timeoutMs = 120_000) {
  return new Promise((resolve, reject) => {
    console.log(`[Node] Spawning: ${PYTHON_BIN} ${PYTHON_RUNNER} ${args.join(" ")}`);

    const child = spawn(PYTHON_BIN, [PYTHON_RUNNER, ...args], {
      cwd: path.dirname(PYTHON_RUNNER), // run from runner/ directory
    });

    let stdoutBuf = "";
    let stderrBuf = "";

    child.stdout.on("data", (chunk) => {
      stdoutBuf += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      const line = chunk.toString().trim();
      if (line) console.log(`[Python] ${line}`); // stream progress to Node console
      stderrBuf += line + "\n";
    });

    // Safety timeout
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error("Python process timed out after " + timeoutMs + "ms"));
    }, timeoutMs);

    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        return reject(
          new Error(`Python exited with code ${code}. stderr: ${stderrBuf.slice(0, 500)}`)
        );
      }
      try {
        // The runner emits exactly ONE JSON object to stdout
        const json = JSON.parse(stdoutBuf.trim());
        resolve(json);
      } catch (parseErr) {
        reject(
          new Error(
            `Failed to parse Python JSON output: ${parseErr.message}\n` +
            `Raw stdout: ${stdoutBuf.slice(0, 500)}`
          )
        );
      }
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to start Python process: ${err.message}`));
    });
  });
}

// ── POST /api/scan ────────────────────────────────────────────────────────────
/**
 * Triggers a full IDSA scan.
 * The Python runner calls all existing scanner modules and returns JSON.
 *
 * Response body shape:
 * {
 *   "scan_id": "scan_20250112_153045",
 *   "timestamp": "...",
 *   "devices": [ { ip, mac, vendor, open_ports, risk_score, cves } ],
 *   "system_info": {...},
 *   "usb_devices": [...],
 *   "vulnerabilities": [...]
 * }
 */
app.post("/api/scan", async (req, res) => {
  console.log("[Node] /api/scan – starting scan …");
  try {
    const scanResult = await spawnPython(["--scan"]);
    res.status(200).json({ success: true, data: scanResult });
  } catch (err) {
    console.error("[Node] Scan error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /api/generate-report ─────────────────────────────────────────────────
/**
 * Generates HTML/JSON/PDF reports and saves them to MOCK_USB.
 *
 * Request body (optional):
 *   { "scanData": { ...the scan JSON object... } }
 *
 * Response body shape:
 * {
 *   "status": "success",
 *   "scan_id": "20250112-153045-abc12345",
 *   "report_dir": "...",
 *   "files": ["...", "...", "..."],
 *   "mock_usb": "..."
 * }
 */
app.post("/api/generate-report", async (req, res) => {
  console.log("[Node] /api/generate-report – generating report …");
  try {
    const args = ["--report"];

    // If the client sends scan data, pass it Base64-encoded to avoid shell escaping issues
    if (req.body && req.body.scanData) {
      const encoded = Buffer.from(JSON.stringify(req.body.scanData)).toString("base64");
      args.push("--scan-data", encoded);
    }

    const reportMeta = await spawnPython(args);
    res.status(200).json({ success: true, data: reportMeta });
  } catch (err) {
    console.error("[Node] Report error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── GET /api/reports ──────────────────────────────────────────────────────────
/**
 * Lists all saved report folders inside MOCK_USB/IDSA_REPORTS/.
 */
app.get("/api/reports", (req, res) => {
  try {
    const folders = fs
      .readdirSync(MOCK_USB_DIR, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => ({
        id: d.name,
        path: path.join(MOCK_USB_DIR, d.name),
        files: fs.readdirSync(path.join(MOCK_USB_DIR, d.name)),
      }))
      .sort((a, b) => b.id.localeCompare(a.id)); // newest first

    res.status(200).json({ success: true, data: folders });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── GET /api/reports/:id/:file ────────────────────────────────────────────────
/**
 * Downloads a specific file from a report folder.
 * Example: GET /api/reports/20250112-153045-abc12345/report_20250112-153045-abc12345.html
 */
app.get("/api/reports/:id/:file", (req, res) => {
  const { id, file } = req.params;
  // Sanitize to prevent path traversal
  const safeId   = path.basename(id);
  const safeFile = path.basename(file);
  const filePath = path.join(MOCK_USB_DIR, safeId, safeFile);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ success: false, error: "File not found" });
  }
  res.download(filePath);
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    python_runner: PYTHON_RUNNER,
    python_bin: PYTHON_BIN,
    mock_usb: MOCK_USB_DIR,
    timestamp: new Date().toISOString(),
  });
});

// ── Serve React build in production (optional) ────────────────────────────────
// When running in production, serve the React build directory from the Node server.
// In development, React runs on its own port (3000) via `npm start` in /frontend.
const REACT_BUILD = path.join(PROJECT_ROOT, "frontend", "build");
if (fs.existsSync(REACT_BUILD)) {
  app.use(express.static(REACT_BUILD));
  // Catch-all: for any route not matched above, serve React's index.html
  app.get("*", (req, res) => {
    res.sendFile(path.join(REACT_BUILD, "index.html"));
  });
  console.log(`📦 Serving React build from ${REACT_BUILD}`);
}

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 IDSA Backend running on http://localhost:${PORT}`);
  console.log(`   Python runner : ${PYTHON_RUNNER}`);
  console.log(`   Python binary : ${PYTHON_BIN}`);
  console.log(`   Mock USB dir  : ${MOCK_USB_DIR}\n`);
});

