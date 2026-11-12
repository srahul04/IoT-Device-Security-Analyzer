// src/components/DeviceCard.jsx
import React, { useState } from "react";

export default function DeviceCard({ device, index }) {
  const [expanded, setExpanded] = useState(false);

  const {
    ip = "Unknown",
    mac = "??:??:??:??:??:??",
    vendor = "Unknown Network Device",
    open_ports = [],
    risk_score = "Informational",
    cves = [],
    fingerprints = [],
    upnp_info = null,
  } = device;

  const isHigh = risk_score === "High" || risk_score === "Critical";
  const isMed = risk_score === "Medium";

  return (
    <div
      className="bg-[#0a0a0a] border border-[#262626] hover:border-[#d4af37] transition-all cursor-pointer p-4"
      onClick={() => setExpanded((v) => !v)}
    >
      {/* Card Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 bg-black border border-[#d4af37] flex items-center justify-center text-[#d4af37] font-mono text-xs font-bold">
            {index + 1}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-white text-sm">{ip}</span>
              {upnp_info && (
                <span className="text-[9px] uppercase font-mono px-1.5 py-0.5 bg-[#d4af37]/10 text-[#d4af37] border border-[#d4af37]/30">
                  UPnP Verified
                </span>
              )}
            </div>
            <p className="text-neutral-400 text-xs truncate mt-0.5">{vendor}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {cves.length > 0 && (
            <span className="bg-red-500/10 text-red-400 border border-red-500/30 px-2 py-0.5 text-[10px] font-mono font-bold">
              {cves.length} CVE{cves.length !== 1 ? "s" : ""}
            </span>
          )}
          <span
            className={`px-2 py-0.5 text-[10px] font-mono font-bold uppercase ${
              isHigh
                ? "bg-red-500/10 text-red-400 border border-red-500/30"
                : isMed
                ? "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                : "bg-[#d4af37]/10 text-[#d4af37] border border-[#d4af37]/30"
            }`}
          >
            {risk_score}
          </span>
          <span className="text-neutral-500 font-mono text-xs ml-1">
            {expanded ? "[-]" : "[+]"}
          </span>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div
          className="mt-4 pt-4 border-t border-[#1f1f1f] space-y-4 text-xs"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Metadata Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono">
            <div>
              <span className="text-neutral-500 block text-[10px] uppercase">IP Address</span>
              <span className="text-white">{ip}</span>
            </div>
            <div>
              <span className="text-neutral-500 block text-[10px] uppercase">MAC Address</span>
              <span className="text-neutral-300">{mac}</span>
            </div>
            <div>
              <span className="text-neutral-500 block text-[10px] uppercase">Identified Device</span>
              <span className="text-white">{vendor}</span>
            </div>
            <div>
              <span className="text-neutral-500 block text-[10px] uppercase">Evaluated Risk</span>
              <span className={isHigh ? "text-red-400" : isMed ? "text-amber-400" : "text-[#d4af37]"}>
                {risk_score}
              </span>
            </div>
          </div>

          {/* UPnP Details */}
          {upnp_info && (
            <div className="bg-[#111111] border border-[#d4af37]/30 p-3 space-y-1 font-mono text-[11px]">
              <span className="text-[#d4af37] font-bold block uppercase text-[10px] mb-1">
                Discovered UPnP / SSDP Profile
              </span>
              {upnp_info.friendly_name && (
                <p><span className="text-neutral-500">Device:</span> <span className="text-white">{upnp_info.friendly_name}</span></p>
              )}
              {upnp_info.manufacturer && (
                <p><span className="text-neutral-500">Manufacturer:</span> <span className="text-white">{upnp_info.manufacturer}</span></p>
              )}
              {upnp_info.model_name && (
                <p><span className="text-neutral-500">Model:</span> <span className="text-white">{upnp_info.model_name} {upnp_info.model_number || ""}</span></p>
              )}
            </div>
          )}

          {/* Open Ports */}
          <div>
            <span className="text-neutral-500 block text-[10px] font-mono uppercase mb-1.5">
              Listening Ports ({open_ports.length})
            </span>
            {open_ports.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {open_ports.map((p) => (
                  <span
                    key={p}
                    className="bg-black border border-[#d4af37]/40 text-[#d4af37] px-2 py-0.5 font-mono text-[11px]"
                  >
                    {p}
                  </span>
                ))}
              </div>
            ) : (
              <span className="text-neutral-500 font-mono text-[11px]">No open ports detected.</span>
            )}
          </div>

          {/* Fingerprints */}
          {fingerprints.length > 0 && (
            <div>
              <span className="text-neutral-500 block text-[10px] font-mono uppercase mb-1.5">
                Service Fingerprints
              </span>
              <div className="space-y-1.5 font-mono text-[11px]">
                {fingerprints.map((fp, i) => (
                  <div key={i} className="bg-[#111111] border border-[#222222] p-2">
                    <span className="text-[#d4af37] font-bold">Port {fp.port}:</span>{" "}
                    <span className="text-white">{fp.service}</span>
                    {fp.server_header && <p className="text-neutral-400 mt-0.5">Server: {fp.server_header}</p>}
                    {fp.title && <p className="text-emerald-400 mt-0.5">Page Title: "{fp.title}"</p>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* CVE References */}
          <div>
            <span className="text-neutral-500 block text-[10px] font-mono uppercase mb-1.5">
              Mapped CVE Vulnerabilities
            </span>
            {cves.length > 0 ? (
              <div className="space-y-1">
                {cves.map((c) => (
                  <div key={c} className="flex items-center gap-2 font-mono text-[11px]">
                    <span className="w-1.5 h-1.5 bg-red-500" />
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${c}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-red-400 hover:underline"
                    >
                      {c}
                    </a>
                    <span className="text-neutral-600 text-[10px]">&rarr; NIST Reference</span>
                  </div>
                ))}
              </div>
            ) : (
              <span className="text-neutral-500 font-mono text-[11px]">
                No specific CVE mapping found for open ports.
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
