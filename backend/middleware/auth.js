// backend/middleware/auth.js
const jwt = require("jsonwebtoken");
const config = require("../config");

function verifyToken(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) {
    return res.status(401).json({ success: false, error: "Access denied. Authorization token required." });
  }

  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : header;
  
  jwt.verify(token, config.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, error: "Invalid or expired authorization token." });
    }
    req.user = decoded;
    next();
  });
}

module.exports = { verifyToken };
