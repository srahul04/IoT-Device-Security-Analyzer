// backend/services/scanService.js
const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawnPython } = require("./pythonRunner");
const config = require("../config");

let cachedScanResult = null;

async function executeScan() {
  const result = await spawnPython(["--scan"]);
  cachedScanResult = result;
  return result;
}

async function generateReport(scanDataOverride = null) {
  const scanPayload = scanDataOverride || cachedScanResult;
  const tempFile = path.join(os.tmpdir(), `idsa_scan_${Date.now()}_${Math.random().toString(36).substring(7)}.json`);

  if (scanPayload) {
    fs.writeFileSync(tempFile, JSON.stringify(scanPayload), "utf-8");
  }

  const args = ["--report"];
  if (fs.existsSync(tempFile)) {
    args.push("--scan-file", tempFile);
  }

  try {
    const reportMeta = await spawnPython(args);
    return reportMeta;
  } finally {
    if (fs.existsSync(tempFile)) {
      try { fs.unlinkSync(tempFile); } catch (e) {}
    }
  }
}

function listReports() {
  if (!fs.existsSync(config.MOCK_USB_DIR)) return [];
  return fs
    .readdirSync(config.MOCK_USB_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => ({
      id: d.name,
      files: fs.readdirSync(path.join(config.MOCK_USB_DIR, d.name)),
    }))
    .sort((a, b) => b.id.localeCompare(a.id));
}

function getReportFilePath(folderName, fileName) {
  const safeId = path.basename(folderName);
  const safeFile = path.basename(fileName);
  const target = path.join(config.MOCK_USB_DIR, safeId, safeFile);
  if (!fs.existsSync(target)) return null;
  return target;
}

module.exports = {
  executeScan,
  generateReport,
  listReports,
  getReportFilePath,
};

