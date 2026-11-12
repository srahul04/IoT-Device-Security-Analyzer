// src/components/DeviceCard.jsx
// Expandable device card displaying IP, Vendor/Model, Fingerprints, UPnP Metadata,
// and CVE exposures.
import React, { useState } from "react";

const RISK_META = {
  Critical:      { badge: "badge-high",   color: "text-red-500",       glow: "#ef444466" },
  High:          { badge: "badge-high",   color: "text-cyber-danger",  glow: "#ef444455" },
  Medium:        { badge: "badge-medium", color: "text-cyber-warning", glow: "#f59e0b44" },
  Low:           { badge: "badge-low",    color: "text-cyber-success", glow: "#10b98144" },
  Informational: { badge: "badge-info",   color: "text-cyber-accent",  glow: "#00d4ff33" },
};

export default function DeviceCard({ device, index }) {
  const [expanded, setExpanded] = useState(false);

  const {
    ip           = "Unknown",
    mac          = "??:??:??:??:??:??",
    vendor       = "Unknown Network Device",
    open_ports   = [],
    risk_score   = "Informational",
    cves         = [],
    fingerprints = [],
    upnp_info    = null,
  } = device;

  const meta = RISK_META[risk_score] || RISK_META["Informational"];

  return (
    <div
      className="cyber-card hover:border-cyber-accent/30 transition-all duration-300 cursor-pointer"
      style={{
        animationDelay: `${index * 60}ms`,
        boxShadow: expanded ? `0 0 30px ${meta.glow}` : "",
      }}
      onClick={() => setExpanded((v) => !v)}
    >
      {/* Card header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        {/* Left: IP + vendor / exact model */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
            <svg viewBox="0 0 24 24" className="w-5 h-5 fill-cyber-accent/70" xmlns="http://www.w3.org/2000/svg">
              <path d="M17 8C8 10 5.9 16.17 3.82 21.34L5.71 22l1-2.3A4.49 4.49 0 0 0 8 20C19 20 22 3 22 3c-1 2-8 2-14 7 1 2 2 4 2 4" />
            </svg>
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <p className="font-mono font-bold text-cyber-text text-base truncate">{ip}</p>
              {upnp_info && (
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  UPnP Verified
                </span>
              )}
            </div>
            <p className="text-cyber-muted text-xs truncate">{vendor}</p>
          </div>
        </div>

        {/* Right: Risk badge + CVE count + expand toggle */}
        <div className="flex items-center gap-3 flex-shrink-0">
          {cves.length > 0 && (
            <span className="badge-high text-xs">
              {cves.length} CVE{cves.length !== 1 ? "s" : ""}
            </span>
          )}
          <span className={meta.badge}>{risk_score}</span>
          <svg
            viewBox="0 0 24 24"
            className={`w-4 h-4 fill-cyber-muted transition-transform duration-200 ${expanded ? "rotate-180" : ""}`}
          >
            <path d="M7.41 8.59 12 13.17l4.59-4.58L18 10l-6 6-6-6 1.41-1.41z" />
          </svg>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div
          className="mt-4 pt-4 border-t border-cyber-border space-y-4 text-sm"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Info grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <InfoRow label="IP Address" value={ip} mono />
            <InfoRow label="MAC Address" value={mac} mono />
            <InfoRow label="Identified Device" value={vendor} />
            <InfoRow label="Assessed Risk" value={<span className={meta.badge}>{risk_score}</span>} />
          </div>

          {/* UPnP Metadata (if broadcasted) */}
          {upnp_info && (
            <div className="bg-cyber-bg/90 border border-cyan-500/30 rounded p-3 text-xs space-y-1">
              <p className="text-cyan-400 font-semibold font-mono uppercase tracking-wider mb-1">
                Discovered UPnP / SSDP Profile
              </p>
              {upnp_info.friendly_name && <p><span className="text-cyber-muted">Device Name:</span> <span className="text-white font-mono">{upnp_info.friendly_name}</span></p>}
              {upnp_info.manufacturer && <p><span className="text-cyber-muted">Manufacturer:</span> <span className="text-white font-mono">{upnp_info.manufacturer}</span></p>}
              {upnp_info.model_name && <p><span className="text-cyber-muted">Model:</span> <span className="text-white font-mono">{upnp_info.model_name} {upnp_info.model_number || ""}</span></p>}
              {upnp_info.server && <p><span className="text-cyber-muted">Software / OS:</span> <span className="text-white font-mono">{upnp_info.server}</span></p>}
            </div>
          )}

          {/* Open ports */}
          <div>
            <p className="text-cyber-muted text-xs uppercase tracking-widest mb-2 font-mono">
              Open Ports ({open_ports.length})
            </p>
            {open_ports.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {open_ports.map((port) => (
                  <span
                    key={port}
                    className="px-2 py-0.5 rounded-md bg-cyber-bg border border-cyber-border text-cyber-accent font-mono text-xs"
                  >
                    {port}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-cyber-muted font-mono text-xs">No listening ports detected</p>
            )}
          </div>

          {/* Service Fingerprints & Web Banners */}
          {fingerprints.length > 0 && (
            <div>
              <p className="text-cyber-muted text-xs uppercase tracking-widest mb-2 font-mono">
                Fingerprinted Services
              </p>
              <div className="space-y-1.5">
                {fingerprints.map((fp, i) => (
                  <div key={i} className="bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-xs font-mono">
                    <div className="flex items-center gap-2">
                      <span className="text-cyber-accent font-bold">Port {fp.port}:</span>
                      <span className="text-white">{fp.service}</span>
                    </div>
                    {fp.server_header && (
                      <p className="text-slate-400 mt-0.5">Server: {fp.server_header}</p>
                    )}
                    {fp.title && (
                      <p className="text-emerald-400 mt-0.5">Page Title: "{fp.title}"</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* CVEs */}
          <div>
            <p className="text-cyber-muted text-xs uppercase tracking-widest mb-2 font-mono">
              CVE Exposures
            </p>
            {cves.length > 0 ? (
              <div className="space-y-1">
                {cves.map((cve) => (
                  <div key={cve} className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyber-danger flex-shrink-0" />
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyber-danger font-mono text-xs hover:underline"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {cve}
                    </a>
                    <span className="text-cyber-muted text-xs">&rarr; NVD Reference</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-cyber-success font-mono text-xs">&check; No known CVEs detected for mapped ports</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function InfoRow({ label, value, mono = false }) {
  return (
    <div>
      <p className="text-cyber-muted text-xs uppercase tracking-widest font-mono mb-0.5">{label}</p>
      <p className={`text-cyber-text text-sm ${mono ? "font-mono" : ""} break-all`}>
        {value}
      </p>
    </div>
  );
}
