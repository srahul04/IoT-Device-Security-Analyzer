// backend/controllers/scanController.js
const scanService = require("../services/scanService");

async function triggerScan(req, res) {
  try {
    const data = await scanService.executeScan();
    return res.json({ success: true, data });
  } catch (err) {
    console.error("[ScanController] Scan failed:", err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
}

async function createReport(req, res) {
  try {
    const scanData = req.body?.scanData || null;
    const reportData = await scanService.generateReport(scanData);
    return res.json({ success: true, data: reportData });
  } catch (err) {
    console.error("[ScanController] Report creation failed:", err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
}

function getReports(req, res) {
  try {
    const reports = scanService.listReports();
    return res.json({ success: true, data: reports });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
}

function downloadReportFile(req, res) {
  const { id, file } = req.params;
  const filePath = scanService.getReportFilePath(id, file);
  if (!filePath) {
    return res.status(404).json({ success: false, error: "Requested report file not found." });
  }
  return res.download(filePath);
}

module.exports = {
  triggerScan,
  createReport,
  getReports,
  downloadReportFile,
};

