// backend/server.js
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const fs = require("fs");
const path = require("path");

const config = require("./config");
const apiRoutes = require("./routes");

const app = express();

// Security and parser middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "15mb" }));

// Mount clean modular API router
app.use("/api", apiRoutes);

// Static frontend serving (Production mode)
if (fs.existsSync(config.REACT_BUILD_DIR)) {
  app.use(express.static(config.REACT_BUILD_DIR));
  app.get("*", (req, res) => {
    res.sendFile(path.join(config.REACT_BUILD_DIR, "index.html"));
  });
  console.log(`[IDSA Host] Serving compiled React UI from: ${config.REACT_BUILD_DIR}`);
}

// Server startup
app.listen(config.PORT, () => {
  console.log(`====================================================`);
  console.log(`  IoT Device Security Analyzer (IDSA) Server`);
  console.log(`====================================================`);
  console.log(`  Port           : http://localhost:${config.PORT}`);
  console.log(`  Engine Runner  : ${config.PYTHON_RUNNER}`);
  console.log(`  Python Binary  : ${config.PYTHON_BIN}`);
  console.log(`  USB Drive Path : ${config.MOCK_USB_DIR}`);
  console.log(`====================================================`);
});
