// src/components/Results.jsx
import React, { useState } from "react";
import DeviceCard from "./DeviceCard";

export default function Results({ data, reportMeta, onGenerateReport, onNewScan }) {
  const [generatingReport, setGeneratingReport] = useState(false);
  const [activeTab, setActiveTab] = useState("vulns");

  const devices = data.devices || [];
  const rawVulns = data.vulnerabilities || [];
  const systemInfo = data.system_info || {};
  const usbDevices = data.usb_devices || [];

  // Sort vulnerabilities High to Low
  const SEV_ORDER = { Critical: 1, High: 2, Medium: 3, Low: 4, Informational: 5 };
  const vulnerabilities = [...rawVulns].sort((a, b) => {
    return (SEV_ORDER[a.severity] || 99) - (SEV_ORDER[b.severity] || 99);
  });

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
      {/* Top Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-[#0a0a0a] border border-[#262626] p-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold uppercase text-white tracking-wide">
              Evaluation <span className="text-[#d4af37]">Results</span>
            </h2>
            <span className="text-[10px] font-mono bg-[#141414] border border-[#d4af37]/40 text-[#d4af37] px-2 py-0.5">
              USB READY
            </span>
          </div>
          <p className="text-neutral-400 text-xs font-mono mt-1">
            Scan ID: {data.scan_id} &bull; Host: {systemInfo.hostname || "Local Machine"} &bull; Architect: Rahul S
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
            {generatingReport ? "Generating Reports..." : "Save Reports to USB"}
          </button>
        </div>
      </div>

      {/* Summary Stat Cards (Boxy Black & Gold) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Total Findings" value={vulnerabilities.length} color="text-[#d4af37]" />
        <StatCard
          label="High / Critical"
          value={vulnerabilities.filter((v) => v.severity === "High" || v.severity === "Critical").length}
          color="text-red-500"
        />
        <StatCard label="Discovered Devices" value={devices.length} color="text-amber-500" />
        <StatCard label="Mapped CVEs" value={totalCVEs} color="text-red-400" />
      </div>

      {/* Report Saved Notification Banner */}
      {reportMeta && (
        <div className="bg-[#0d0d0d] border border-[#d4af37] p-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[#d4af37] font-bold text-xs uppercase tracking-wider flex items-center gap-1.5">
              <span>&#9632;</span> All Reports Successfully Written to USB Media
            </p>
            <p className="text-neutral-400 text-xs font-mono mt-1">
              Location: {reportMeta.report_dir}
            </p>
            <p className="text-neutral-500 text-[11px] font-mono mt-0.5">
              Formats: Valid Binary PDF (%PDF-1.4), Standalone Interactive HTML, Structured JSON
            </p>
          </div>
          <div className="text-xs font-mono text-neutral-400 space-y-1">
            {(reportMeta.files || []).map((f) => (
              <p key={f} className="truncate max-w-xs text-[#d4af37]">
                &bull; {f.split(/[\\/]/).pop()}
              </p>
            ))}
          </div>
        </div>
      )}

      {/* Tab Navigation (Boxy) */}
      <div className="flex gap-1 border-b border-[#262626] overflow-x-auto">
        {[
          { key: "vulns", label: `Prioritized Findings (${vulnerabilities.length})` },
          { key: "devices", label: `Discovered Devices (${devices.length})` },
          { key: "system", label: "Host Telemetry" },
          { key: "usb", label: `USB Peripherals (${usbDevices.length})` },
        ].map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`
              px-4 py-2.5 text-xs font-mono uppercase tracking-wider whitespace-nowrap border-b-2 transition-colors rounded-none
              ${
                activeTab === key
                  ? "border-[#d4af37] text-[#d4af37] bg-[#0f0f0f]"
                  : "border-transparent text-neutral-400 hover:text-white"
              }
            `}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab 1: Prioritized Findings & Remediation */}
      {activeTab === "vulns" && (
        <div className="space-y-3">
          {vulnerabilities.length === 0 ? (
            <EmptyState msg="No security weaknesses recorded on this target." />
          ) : (
            vulnerabilities.map((v, i) => (
              <div
                key={i}
                className="bg-[#0a0a0a] border border-[#262626] p-4 text-xs space-y-2 border-l-4"
                style={{
                  borderLeftColor:
                    v.severity === "Critical" || v.severity === "High"
                      ? "#ef4444"
                      : v.severity === "Medium"
                      ? "#f59e0b"
                      : "#d4af37",
                }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span
                      className={`font-mono text-[10px] uppercase font-bold px-2 py-0.5 ${
                        v.severity === "High" || v.severity === "Critical"
                          ? "bg-red-500/10 text-red-400 border border-red-500/30"
                          : v.severity === "Medium"
                          ? "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                          : "bg-[#d4af37]/10 text-[#d4af37] border border-[#d4af37]/30"
                      }`}
                    >
                      {v.severity}
                    </span>
                    <span className="font-mono text-neutral-400 uppercase text-[11px]">
                      {v.module || "Security Scanner"}
                    </span>
                  </div>
                </div>

                <p className="text-white font-medium text-sm leading-snug">{v.description}</p>

                {v.recommendation && (
                  <div className="bg-[#121212] border border-[#1f1f1f] p-2.5 mt-2">
                    <span className="text-[#d4af37] font-semibold font-mono block mb-0.5 text-[11px] uppercase">
                      Actionable Recommendation:
                    </span>
                    <span className="text-neutral-300 font-mono text-[11px] leading-relaxed">
                      {v.recommendation}
                    </span>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 2: Discovered Devices */}
      {activeTab === "devices" && (
        <div>
          {devices.length === 0 ? (
            <EmptyState msg="No active devices discovered on this network range." />
          ) : (
            <div className="space-y-3">
              <p className="text-neutral-400 text-xs font-mono">
                Subnet: <span className="text-white">{data.network_range}</span> &bull; Gateway / Interface:{" "}
                <span className="text-white">{data.local_ip}</span>
              </p>
              {devices.map((device, i) => (
                <DeviceCard key={device.ip || i} device={device} index={i} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Host Telemetry */}
      {activeTab === "system" && (
        <div className="bg-[#0a0a0a] border border-[#262626] p-4">
          <pre className="text-xs font-mono text-neutral-300 overflow-auto max-h-96 leading-relaxed">
            {JSON.stringify(systemInfo, null, 2)}
          </pre>
        </div>
      )}

      {/* Tab 4: USB Peripherals */}
      {activeTab === "usb" && (
        <div className="space-y-3">
          {usbDevices.length === 0 ? (
            <EmptyState msg="No external USB peripherals attached." />
          ) : (
            usbDevices.map((usb, i) => (
              <div key={i} className="bg-[#0a0a0a] border border-[#262626] p-4">
                <pre className="text-xs font-mono text-neutral-300">
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
    <div className="bg-[#0a0a0a] border border-[#262626] p-4 text-center space-y-1">
      <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
      <p className="text-neutral-400 text-[10px] font-mono uppercase tracking-widest">{label}</p>
    </div>
  );
}

function EmptyState({ msg }) {
  return (
    <div className="bg-[#0a0a0a] border border-[#262626] text-center py-10 space-y-1">
      <p className="text-neutral-500 font-mono text-xs">{msg}</p>
    </div>
  );
}
