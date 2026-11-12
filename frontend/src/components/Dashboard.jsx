// src/components/Dashboard.jsx
//
// Shows the main control panel with:
//  - System status overview
//  - "Start Scan" button
//  - Animated scanning state
//  - Error display
import React from "react";

const SCAN_STEPS = [
  "Initializing scanner modules …",
  "Collecting system information …",
  "Enumerating USB devices …",
  "Running network ping sweep …",
  "Scanning open ports …",
  "Querying CVE database …",
  "Checking configuration issues …",
  "Finalising results …",
];

export default function Dashboard({ phase, errorMsg, onStartScan }) {
  const isScanning = phase === "scanning";
  const isError    = phase === "error";

  // Cycle through scan step messages every 2 s while scanning
  const [stepIdx, setStepIdx] = React.useState(0);
  React.useEffect(() => {
    if (!isScanning) { setStepIdx(0); return; }
    const id = setInterval(() => {
      setStepIdx((i) => (i + 1) % SCAN_STEPS.length);
    }, 2000);
    return () => clearInterval(id);
  }, [isScanning]);

  return (
    <div className="space-y-8">
      {/* ── Hero section ─────────────────────────────────────────────────── */}
      <div className="text-center space-y-3 pt-6">
        <h2 className="text-4xl font-bold tracking-tight">
          <span className="cyber-accent">IoT</span> Security{" "}
          <span className="text-cyber-accent2">Scanner</span>
        </h2>
        <p className="text-cyber-muted max-w-xl mx-auto text-sm leading-relaxed">
          Discover active network devices, detect open ports, map CVE exposures,
          and generate a full security report – all from one dashboard.
        </p>
      </div>

      {/* ── Scan control card ─────────────────────────────────────────────── */}
      <div
        className="cyber-card max-w-2xl mx-auto text-center space-y-6"
        style={isScanning ? { boxShadow: "0 0 40px #00d4ff22" } : {}}
      >
        {/* Animated radar icon */}
        <div className="flex justify-center">
          <div className={`relative w-28 h-28 ${isScanning ? "animate-pulse_slow" : ""}`}>
            {/* Outer rings */}
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className={`
                  absolute inset-0 rounded-full border
                  ${isScanning ? "border-cyber-accent/40 animate-ping" : "border-cyber-border"}
                `}
                style={{ animationDelay: `${i * 0.4}s`, animationDuration: "2s" }}
              />
            ))}
            {/* Center button */}
            <div className="absolute inset-4 rounded-full bg-cyber-accent/10 border border-cyber-accent/40 flex items-center justify-center">
              <svg viewBox="0 0 24 24" className={`w-8 h-8 fill-cyber-accent ${isScanning ? "animate-spin" : ""}`} style={{ animationDuration: "4s" }}>
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 14.5v-9l6 4.5-6 4.5z" />
              </svg>
            </div>
          </div>
        </div>

        {/* Status text */}
        <div>
          {isScanning ? (
            <div className="space-y-2">
              <p className="text-cyber-accent font-mono text-sm animate-pulse">
                ■ SCAN IN PROGRESS
              </p>
              <p className="text-cyber-muted text-xs font-mono transition-all duration-500">
                {SCAN_STEPS[stepIdx]}
              </p>
              {/* Progress bar */}
              <div className="w-full bg-cyber-border rounded-full h-1 mt-3 overflow-hidden">
                <div
                  className="h-full bg-cyber-accent rounded-full transition-all duration-1000"
                  style={{
                    width: `${((stepIdx + 1) / SCAN_STEPS.length) * 100}%`,
                    boxShadow: "0 0 8px #00d4ff",
                  }}
                />
              </div>
            </div>
          ) : isError ? (
            <div className="space-y-2">
              <p className="text-cyber-danger font-mono text-sm">✗ SCAN FAILED</p>
              <p className="text-cyber-muted text-xs font-mono break-all">{errorMsg}</p>
            </div>
          ) : (
            <div>
              <p className="text-cyber-text font-semibold">Ready to Scan</p>
              <p className="text-cyber-muted text-xs mt-1 font-mono">
                Click below to start a full IoT network security analysis
              </p>
            </div>
          )}
        </div>

        {/* Action button */}
        <button
          onClick={onStartScan}
          disabled={isScanning}
          className={`
            ${isScanning ? "opacity-50 cursor-not-allowed btn-ghost" : "btn-primary"}
            min-w-[200px]
          `}
        >
          {isScanning ? "Scanning …" : isError ? "Retry Scan" : "Start Scan"}
        </button>
      </div>

      {/* ── Info cards row ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-2xl mx-auto">
        {[
          { icon: "🌐", title: "Network Discovery", desc: "Ping sweep + port scan on your LAN" },
          { icon: "🛡", title: "CVE Detection",     desc: "Maps open ports to known CVE IDs" },
          { icon: "💾", title: "Report Export",    desc: "Saves JSON / HTML / PDF to MOCK_USB" },
        ].map((item) => (
          <div key={item.title} className="cyber-card text-center space-y-2 hover:border-cyber-accent/40 transition-colors">
            <span className="text-2xl">{item.icon}</span>
            <p className="font-semibold text-sm">{item.title}</p>
            <p className="text-cyber-muted text-xs font-mono">{item.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

