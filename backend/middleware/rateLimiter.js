// backend/middleware/rateLimiter.js
const rateLimit = require("express-rate-limit");

const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many scan requests. Please wait a minute." },
});

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Too many authentication requests." },
});

module.exports = { scanLimiter, authLimiter };
