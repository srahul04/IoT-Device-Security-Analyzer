// backend/controllers/authController.js
const jwt = require("jsonwebtoken");
const os = require("os");
const config = require("../config");

function approveSession(req, res) {
  const { approval } = req.body;
  if (config.REQUIRE_APPROVAL && approval !== "IAGREE") {
    return res.status(403).json({ success: false, error: "Physical approval consent not provided." });
  }

  const token = jwt.sign(
    {
      host: os.hostname(),
      issuedAt: new Date().toISOString(),
    },
    config.JWT_SECRET,
    { expiresIn: "8h" }
  );

  return res.json({ success: true, token });
}

module.exports = { approveSession };
