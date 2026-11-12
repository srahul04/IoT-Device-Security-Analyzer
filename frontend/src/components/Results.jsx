// src/components/Results.jsx
//
// Full scan results panel.
// Props:
//   data            – raw JSON from /api/scan
//   reportMeta      – report generation metadata (or null)
//   onGenerateReport – callback to trigger POST /api/generate-report
//   onNewScan        – callback to reset to idle
import React, { useState } from "react";
import DeviceCard from "./DeviceCard";

export default function Results({ data, reportMeta, onGenerateReport, onNewScan }) {
  const [generatingReport, setGeneratingReport] = useState(false);
  const [activeTab, setActiveTab]               = useState("devices");

  const devices        = data.devices        || [];
  const vulnerabilities = data.vulnerabilities || [];
  const systemInfo     = data.system_info    || {};
  const usbDevices     = data.usb_devices    || [];

  // Risk summary counts
  const riskCounts = devices.reduce(
    (acc, d) => {
      const r = d.risk_score || "Informational";
      acc[r] = (acc[r] || 0) + 1;
      return acc;
    },
    { High: 0, Medium: 0, Low: 0, Informational: 0 }
  );

  const totalCVEs = devices.reduce((sum, d) => sum + (d.cves?.length || 0), 0);

  // ── Report generation handler ─────────────────────────────────────────────
  const handleReport = async () => {
    setGeneratingReport(true);
    try {
      await onGenerateReport();
    } finally {
      setGeneratingReport(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* ── Top toolbar ───────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold">
            Scan&nbsp;<span className="cyber-accent">Results</span>
          </h2>
          <p className="text-cyber-muted text-xs font-mono mt-1">
            Scan ID: {data.scan_id} · {data.timestamp?.slice(0, 19).replace("T", " ")}
          </p>
        </div>
        <div className="flex gap-3">
          <button onClick={onNewScan} className="btn-ghost">
            ↩ New Scan
          </button>
          <button
            onClick={handleReport}
            disabled={generatingReport}
            className={generatingReport ? "btn-ghost opacity-50 cursor-not-allowed" : "btn-primary"}
          >
            {generatingReport ? "Generating …" : "💾 Download Report"}
          </button>
        </div>
      </div>

      {/* ── Summary stat cards ────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard label="Devices Found"  value={devices.length}       color="text-cyber-accent" />
        <StatCard label="High Risk"      value={riskCounts.High}      color="text-cyber-danger" />
        <StatCard label="Medium Risk"    value={riskCounts.Medium}    color="text-cyber-warning" />
        <StatCard label="Total CVEs"     value={totalCVEs}            color="text-cyber-danger" />
      </div>

      {/* ── Report saved banner ───────────────────────────────────────────── */}
      {reportMeta && (
        <div className="cyber-card border-cyber-success/40 bg-cyber-success/5 flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-cyber-success font-semibold">✓ Report Saved to Mock USB Drive</p>
            <p className="text-cyber-muted text-xs font-mono mt-1">
              Scan ID: {reportMeta.scan_id}
            </p>
            <p className="text-cyber-muted text-xs font-mono">
              Location: {reportMeta.mock_usb}
            </p>
          </div>
          <div className="text-xs font-mono text-cyber-muted space-y-1">
            {(reportMeta.files || []).map((f) => (
              <p key={f} className="truncate max-w-xs">📄 {f.split(/[\\/]/).pop()}</p>
            ))}
          </div>
        </div>
      )}

      {/* ── Tabs ──────────────────────────────────────────────────────────── */}
      <div className="flex gap-1 border-b border-cyber-border overflow-x-auto">
        {[
          { key: "devices",  label: `Devices (${devices.length})` },
          { key: "vulns",    label: `Vulnerabilities (${vulnerabilities.length})` },
          { key: "system",   label: "System Info" },
          { key: "usb",      label: `USB (${usbDevices.length})` },
        ].map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`
              px-4 py-2 text-sm font-mono whitespace-nowrap border-b-2 transition-colors
              ${activeTab === key
                ? "border-cyber-accent text-cyber-accent"
                : "border-transparent text-cyber-muted hover:text-cyber-text"}
            `}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Tab: Device Cards ─────────────────────────────────────────────── */}
      {activeTab === "devices" && (
        <div>
          {devices.length === 0 ? (
            <EmptyState msg="No active devices discovered on this network." />
          ) : (
            <div className="space-y-4">
              <p className="text-cyber-muted text-xs font-mono">
                Network range: <span className="text-cyber-text">{data.network_range}</span>
                {" · "}Local IP: <span className="text-cyber-text">{data.local_ip}</span>
              </p>
              {devices.map((device, i) => (
                <DeviceCard key={device.ip || i} device={device} index={i} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Tab: Vulnerabilities ──────────────────────────────────────────── */}
      {activeTab === "vulns" && (
        <div className="space-y-3">
          {vulnerabilities.length === 0 ? (
            <EmptyState msg="No vulnerabilities recorded." icon="✓" good />
          ) : (
            vulnerabilities.map((v, i) => (
              <div key={i} className="cyber-card flex gap-4 items-start">
                <span
                  className={`flex-shrink-0 mt-0.5 ${
                    v.severity === "High"   ? "text-cyber-danger"  :
                    v.severity === "Medium" ? "text-cyber-warning" :
                    "text-cyber-success"
                  }`}
                >
                  {v.severity === "High" ? "▲" : v.severity === "Medium" ? "●" : "▼"}
                </span>
                <div>
                  <p className="font-mono text-xs text-cyber-muted uppercase tracking-wider">
                    {v.module || "Scanner"} · {v.severity}
                  </p>
                  <p className="text-cyber-text text-sm mt-0.5">{v.description}</p>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* ── Tab: System Info ──────────────────────────────────────────────── */}
      {activeTab === "system" && (
        <div className="cyber-card">
          <pre className="text-xs font-mono text-cyber-muted overflow-auto max-h-96 leading-relaxed">
            {JSON.stringify(systemInfo, null, 2)}
          </pre>
        </div>
      )}

      {/* ── Tab: USB Devices ──────────────────────────────────────────────── */}
      {activeTab === "usb" && (
        <div className="space-y-3">
          {usbDevices.length === 0 ? (
            <EmptyState msg="No USB devices detected." />
          ) : (
            usbDevices.map((usb, i) => (
              <div key={i} className="cyber-card">
                <pre className="text-xs font-mono text-cyber-muted">
                  {JSON.stringify(usb, null, 2)}
                </pre>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

// ── Helper components ─────────────────────────────────────────────────────────

function StatCard({ label, value, color }) {
  return (
    <div className="cyber-card text-center space-y-1">
      <p className={`text-3xl font-bold font-mono ${color}`}>{value}</p>
      <p className="text-cyber-muted text-xs uppercase tracking-widest">{label}</p>
    </div>
  );
}

function EmptyState({ msg, icon = "○", good = false }) {
  return (
    <div className="cyber-card text-center py-10 space-y-2">
      <p className={`text-3xl ${good ? "text-cyber-success" : "text-cyber-muted"}`}>{icon}</p>
      <p className="text-cyber-muted font-mono text-sm">{msg}</p>
    </div>
  );
}

