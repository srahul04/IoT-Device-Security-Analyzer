// backend/routes/index.js
const express = require("express");
const router = express.Router();

const { verifyToken } = require("../middleware/auth");
const { scanLimiter, authLimiter } = require("../middleware/rateLimiter");

const authController = require("../controllers/authController");
const scanController = require("../controllers/scanController");
const systemController = require("../controllers/systemController");

// Public endpoints
router.get("/health", systemController.getHealth);
router.post("/approve", authLimiter, authController.approveSession);

// Protected endpoints
router.post("/scan", scanLimiter, verifyToken, scanController.triggerScan);
router.post("/generate-report", verifyToken, scanController.createReport);
router.get("/reports", verifyToken, scanController.getReports);
router.get("/reports/:id/:file", verifyToken, scanController.downloadReportFile);

module.exports = router;
