// backend/services/pythonRunner.js
const { spawn } = require("child_process");
const path = require("path");
const config = require("../config");

function spawnPython(args, timeoutMs = 180000) {
  return new Promise((resolve, reject) => {
    const child = spawn(config.PYTHON_BIN, [config.PYTHON_RUNNER, ...args], {
      cwd: path.dirname(config.PYTHON_RUNNER),
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });

    child.stderr.on("data", (d) => {
      const line = d.toString().trim();
      if (line) console.log(`[Python Engine] ${line}`);
      stderr += line + "\n";
    });

    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error("Python scanner process timed out"));
    }, timeoutMs);

    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        return reject(new Error(`Python scanner exited with code ${code}: ${stderr.slice(0, 500)}`));
      }
      try {
        const parsed = JSON.parse(stdout.trim());
        resolve(parsed);
      } catch (e) {
        reject(new Error(`Invalid JSON output from scanner: ${stdout.slice(0, 200)}`));
      }
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to start Python process: ${err.message}`));
    });
  });
}

module.exports = { spawnPython };
