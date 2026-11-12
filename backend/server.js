/**
 * server.js
 * IDSA Express backend
 *
 * Routes:
 *   POST /api/approve          issue a session token after physical consent
 *   POST /api/scan             run full scan, returns JSON
 *   POST /api/generate-report  generate report files, save to MOCK_USB
 *   GET  /api/reports          list saved report folders
 *   GET  /api/reports/:id/:file download a report file
 *   GET  /api/health           health check
 *
 * Start: node server.js
 */

require("dotenv").config({ path: require("path").resolve(__dirname, "../.env") });

const express      = require("express");
const cors         = require("cors");
const path         = require("path");
const fs           = require("fs");
const os           = require("os");
const { spawn }    = require("child_process");
const jwt          = require("jsonwebtoken");
const rateLimit    = require("express-rate-limit");
const helmet       = require("helmet");

const app  = express();
const PORT = process.env.SERVER_PORT || 5000;

const JWT_SECRET          = process.env.JWT_SECRET;
const REQUIRE_APPROVAL    = process.env.REQUIRE_USER_APPROVAL !== "false";

if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET is not set. Copy .env.example to .env and set a secret.");
  process.exit(1);
}

// Paths
const PROJECT_ROOT  = path.resolve(__dirname, "..");
const PYTHON_RUNNER = path.join(PROJECT_ROOT, "IDSA_Existing", "runner", "scan_runner.py");
const VENV_PYTHON   = path.join(PROJECT_ROOT, "IDSA_Existing", ".venv", "Scripts", "python.exe");
const PYTHON_BIN    = process.env.PYTHON_PATH
  ? path.resolve(PROJECT_ROOT, process.env.PYTHON_PATH)
  : fs.existsSync(VENV_PYTHON) ? VENV_PYTHON : "python";

const MOCK_USB_DIR = path.join(PROJECT_ROOT, "MOCK_USB", "IDSA_REPORTS");
fs.mkdirSync(MOCK_USB_DIR, { recursive: true });

// Security middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "2mb" }));

// Rate limiting
const scanLimiter = rateLimit({ windowMs: 60_000, max: 10, message: { error: "Too many requests." } });
const authLimiter = rateLimit({ windowMs: 60_000, max: 20, message: { error: "Too many requests." } });

// JWT middleware
function verifyToken(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(401).json({ error: "Missing token" });
  const token = header.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
}

// Python spawner
function spawnPython(args, timeoutMs = 120_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON_BIN, [PYTHON_RUNNER, ...args], {
      cwd: path.dirname(PYTHON_RUNNER),
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", d => (stdout += d.toString()));
    child.stderr.on("data", d => {
      const line = d.toString().trim();
      if (line) console.log(`[Python] ${line}`);
      stderr += line + "\n";
    });

    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error("Python process timed out"));
    }, timeoutMs);

    child.on("close", code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(`Python exited ${code}: ${stderr.slice(0, 500)}`));
      try {
        resolve(JSON.parse(stdout.trim()));
      } catch (e) {
        reject(new Error(`Invalid JSON from Python: ${stdout.slice(0, 200)}`));
      }
    });

    child.on("error", err => {
      clearTimeout(timer);
      reject(new Error(`Could not start Python: ${err.message}`));
    });
  });
}

// POST /api/approve
app.post("/api/approve", authLimiter, (req, res) => {
  const { approval } = req.body;
  if (REQUIRE_APPROVAL && approval !== "IAGREE") {
    return res.status(403).json({ error: "Physical approval not given." });
  }
  const token = jwt.sign({ host: os.hostname() }, JWT_SECRET, { expiresIn: "8h" });
  res.json({ token });
});

// POST /api/scan
app.post("/api/scan", scanLimiter, verifyToken, async (req, res) => {
  console.log("[Node] /api/scan requested");
  try {
    const result = await spawnPython(["--scan"]);
    res.json({ success: true, data: result });
  } catch (err) {
    console.error("[Node] Scan error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/generate-report
app.post("/api/generate-report", verifyToken, async (req, res) => {
  console.log("[Node] /api/generate-report requested");
  try {
    const args = ["--report"];
    if (req.body?.scanData) {
      const encoded = Buffer.from(JSON.stringify(req.body.scanData)).toString("base64");
      args.push("--scan-data", encoded);
    }
    const result = await spawnPython(args);
    res.json({ success: true, data: result });
  } catch (err) {
    console.error("[Node] Report error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/reports
app.get("/api/reports", verifyToken, (req, res) => {
  try {
    const folders = fs
      .readdirSync(MOCK_USB_DIR, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => ({
        id:    d.name,
        files: fs.readdirSync(path.join(MOCK_USB_DIR, d.name)),
      }))
      .sort((a, b) => b.id.localeCompare(a.id));
    res.json({ success: true, data: folders });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/reports/:id/:file
app.get("/api/reports/:id/:file", verifyToken, (req, res) => {
  const safeId   = path.basename(req.params.id);
  const safeFile = path.basename(req.params.file);
  const filePath = path.join(MOCK_USB_DIR, safeId, safeFile);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found" });
  res.download(filePath);
});

// GET /api/health
app.get("/api/health", (req, res) => {
  res.json({
    status:  "ok",
    host:    os.hostname(),
    python:  PYTHON_BIN,
    mock_usb: MOCK_USB_DIR,
    time:    new Date().toISOString(),
  });
});

// Serve React build
const REACT_BUILD = path.join(PROJECT_ROOT, "frontend", "build");
if (fs.existsSync(REACT_BUILD)) {
  app.use(express.static(REACT_BUILD));
  app.get("*", (req, res) =>
    res.sendFile(path.join(REACT_BUILD, "index.html"))
  );
  console.log(`[Node] Serving React build from ${REACT_BUILD}`);
}

app.listen(PORT, () => {
  console.log(`[Node] IDSA backend running on http://localhost:${PORT}`);
  console.log(`[Node] Python runner: ${PYTHON_RUNNER}`);
  console.log(`[Node] Python binary: ${PYTHON_BIN}`);
  console.log(`[Node] Mock USB dir:  ${MOCK_USB_DIR}`);
});
