// src/components/Results.jsx
// Results panel displaying discovered IoT devices, enhanced security posture findings,
// and actionable recommendations for each vulnerability.
import React, { useState } from "react";
import DeviceCard from "./DeviceCard";

export default function Results({ data, reportMeta, onGenerateReport, onNewScan }) {
  const [generatingReport, setGeneratingReport] = useState(false);
  const [activeTab, setActiveTab]               = useState("vulns");

  const devices         = data.devices         || [];
  const vulnerabilities = data.vulnerabilities || [];
  const systemInfo      = data.system_info     || {};
  const usbDevices      = data.usb_devices     || [];

  const riskCounts = devices.reduce(
    (acc, d) => {
      const r = d.risk_score || "Informational";
      acc[r] = (acc[r] || 0) + 1;
      return acc;
    },
    { High: 0, Medium: 0, Low: 0, Informational: 0 }
  );

  const totalCVEs = devices.reduce((sum, d) => sum + (d.cves?.length || 0), 0);

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
      {/* Top toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold">
            Audit &nbsp;<span className="cyber-accent">Results</span>
          </h2>
          <p className="text-cyber-muted text-xs font-mono mt-1">
            Scan ID: {data.scan_id} &bull; Host: {data.system_info?.hostname || "Local Machine"}
          </p>
        </div>
        <div className="flex gap-3">
          <button onClick={onNewScan} className="btn-ghost">
            &#8634; New Scan
          </button>
          <button
            onClick={handleReport}
            disabled={generatingReport}
            className={generatingReport ? "btn-ghost opacity-50 cursor-not-allowed" : "btn-primary"}
          >
            {generatingReport ? "Generating..." : "Generate & Save Report"}
          </button>
        </div>
      </div>

      {/* Summary stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard label="Total Findings" value={vulnerabilities.length} color="text-cyber-accent" />
        <StatCard label="High / Critical" value={vulnerabilities.filter(v => v.severity === "High" || v.severity === "Critical").length} color="text-cyber-danger" />
        <StatCard label="Devices Discovered" value={devices.length} color="text-cyber-warning" />
        <StatCard label="Total CVEs" value={totalCVEs} color="text-cyber-danger" />
      </div>

      {/* Report saved banner */}
      {reportMeta && (
        <div className="cyber-card border-cyber-success/40 bg-cyber-success/5 flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-cyber-success font-semibold">&check; Report Saved to USB Drive</p>
            <p className="text-cyber-muted text-xs font-mono mt-1">
              Folder: {reportMeta.report_dir}
            </p>
            <p className="text-cyber-muted text-xs font-mono mt-0.5">
              Available Formats: Genuine PDF, Interactive HTML, Structured JSON
            </p>
          </div>
          <div className="text-xs font-mono text-cyber-muted space-y-1">
            {(reportMeta.files || []).map((f) => (
              <p key={f} className="truncate max-w-xs text-cyber-accent">&bull; {f.split(/[\\/]/).pop()}</p>
            ))}
          </div>
        </div>
      )}

      {/* Navigation tabs */}
      <div className="flex gap-1 border-b border-cyber-border overflow-x-auto">
        {[
          { key: "vulns",    label: `Findings & Recommendations (${vulnerabilities.length})` },
          { key: "devices",  label: `IoT Devices (${devices.length})` },
          { key: "system",   label: "System & Posture" },
          { key: "usb",      label: `USB Devices (${usbDevices.length})` },
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

      {/* Tab: Findings & Actionable Recommendations */}
      {activeTab === "vulns" && (
        <div className="space-y-4">
          {vulnerabilities.length === 0 ? (
            <EmptyState msg="No security weaknesses detected." icon="&check;" good />
          ) : (
            vulnerabilities.map((v, i) => (
              <div key={i} className="cyber-card flex flex-col md:flex-row gap-4 items-start border-l-4"
                style={{
                  borderLeftColor: v.severity === "Critical" || v.severity === "High" ? "#ef4444" :
                                   v.severity === "Medium" ? "#f59e0b" : "#00d4ff"
                }}
              >
                <div className="flex-1 space-y-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs font-bold px-2 py-0.5 rounded font-mono ${
                        v.severity === "High" || v.severity === "Critical" ? "bg-red-500/20 text-red-400 border border-red-500/30" :
                        v.severity === "Medium" ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30" :
                        "bg-blue-500/20 text-cyan-400 border border-cyan-500/30"
                      }`}
                    >
                      {v.severity}
                    </span>
                    <span className="font-mono text-xs text-cyber-muted uppercase tracking-wider">
                      {v.module || "Security Scanner"}
                    </span>
                  </div>
                  <p className="text-cyber-text text-sm font-semibold">{v.description}</p>
                  
                  {v.recommendation && (
                    <div className="mt-2 bg-cyber-bg/80 border border-cyber-border/70 rounded p-3 text-xs">
                      <span className="text-emerald-400 font-semibold block mb-1">
                        Recommendation & Remediation:
                      </span>
                      <span className="text-slate-300 font-mono leading-relaxed">
                        {v.recommendation}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab: Device Cards */}
      {activeTab === "devices" && (
        <div>
          {devices.length === 0 ? (
            <EmptyState msg="No active devices discovered on this network range." />
          ) : (
            <div className="space-y-4">
              <p className="text-cyber-muted text-xs font-mono">
                Subnet: <span className="text-cyber-text">{data.network_range}</span>
                {" &bull; "}Gateway/Interface: <span className="text-cyber-text">{data.local_ip}</span>
              </p>
              {devices.map((device, i) => (
                <DeviceCard key={device.ip || i} device={device} index={i} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab: System & Host Info */}
      {activeTab === "system" && (
        <div className="cyber-card">
          <pre className="text-xs font-mono text-cyber-muted overflow-auto max-h-96 leading-relaxed">
            {JSON.stringify(systemInfo, null, 2)}
          </pre>
        </div>
      )}

      {/* Tab: USB Devices */}
      {activeTab === "usb" && (
        <div className="space-y-3">
          {usbDevices.length === 0 ? (
            <EmptyState msg="No USB devices connected." />
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

function StatCard({ label, value, color }) {
  return (
    <div className="cyber-card text-center space-y-1">
      <p className={`text-3xl font-bold font-mono ${color}`}>{value}</p>
      <p className="text-cyber-muted text-xs uppercase tracking-widest">{label}</p>
    </div>
  );
}

function EmptyState({ msg, icon = "o", good = false }) {
  return (
    <div className="cyber-card text-center py-10 space-y-2">
      <p className={`text-3xl ${good ? "text-cyber-success" : "text-cyber-muted"}`}>{icon}</p>
      <p className="text-cyber-muted font-mono text-sm">{msg}</p>
    </div>
  );
}
