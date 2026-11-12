// backend/config/index.js
const path = require("path");
const fs = require("fs");

require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });

const PROJECT_ROOT = path.resolve(__dirname, "../..");
const PYTHON_RUNNER = path.join(PROJECT_ROOT, "IDSA_Existing", "runner", "scan_runner.py");
const VENV_PYTHON = path.join(PROJECT_ROOT, "IDSA_Existing", ".venv", "Scripts", "python.exe");

const PYTHON_BIN = process.env.PYTHON_PATH
  ? path.resolve(PROJECT_ROOT, process.env.PYTHON_PATH)
  : fs.existsSync(VENV_PYTHON)
  ? VENV_PYTHON
  : "python";

const MOCK_USB_DIR = path.join(PROJECT_ROOT, "MOCK_USB", "IDSA_REPORTS");
fs.mkdirSync(MOCK_USB_DIR, { recursive: true });

const REACT_BUILD_DIR = path.join(PROJECT_ROOT, "frontend", "build");

module.exports = {
  PORT: process.env.SERVER_PORT || 5000,
  JWT_SECRET: process.env.JWT_SECRET || "default_fallback_secret_change_in_production",
  REQUIRE_APPROVAL: process.env.REQUIRE_USER_APPROVAL !== "false",
  PROJECT_ROOT,
  PYTHON_RUNNER,
  PYTHON_BIN,
  MOCK_USB_DIR,
  REACT_BUILD_DIR,
};

