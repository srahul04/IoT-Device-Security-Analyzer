// backend/controllers/systemController.js
const os = require("os");
const config = require("../config");

function getHealth(req, res) {
  return res.json({
    status: "ok",
    host: os.hostname(),
    platform: os.platform(),
    python: config.PYTHON_BIN,
    mock_usb: config.MOCK_USB_DIR,
    timestamp: new Date().toISOString(),
  });
}

module.exports = { getHealth };
