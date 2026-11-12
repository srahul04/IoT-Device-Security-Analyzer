// src/components/Dashboard.jsx
import React from "react";

const SCAN_STEPS = [
  "Initializing security audit modules...",
  "Collecting OS telemetry & host hardware profile...",
  "Enumerating physical USB controllers & devices...",
  "Broadcasting SSDP / UPnP M-SEARCH queries (239.255.255.250:1900)...",
  "Running concurrent subnet ping sweeps...",
  "Auditing open IoT ports & extracting service banners...",
  "Probing specialized IoT protocols (MQTT, RTSP camera streams)...",
  "Auditing factory default web credentials (safe checks)...",
  "Inspecting process memory & suspicious temp paths...",
  "Checking persistence (Registry Run keys, Scheduled Tasks)...",
  "Compiling multi-vector vulnerability dataset...",
];

export default function Dashboard({ phase, errorMsg, onStartScan }) {
  const isScanning = phase === "scanning";
  const isError = phase === "error";

  const [stepIdx, setStepIdx] = React.useState(0);
  React.useEffect(() => {
    if (!isScanning) {
      setStepIdx(0);
      return;
    }
    const id = setInterval(() => {
      setStepIdx((i) => (i + 1) % SCAN_STEPS.length);
    }, 1800);
    return () => clearInterval(id);
  }, [isScanning]);

  return (
    <div className="space-y-8">
      {/* Hero Title */}
      <div className="text-center space-y-2 pt-4">
        <div className="inline-block border border-[#d4af37] px-3 py-0.5 text-[11px] font-mono uppercase tracking-widest text-[#d4af37] mb-2 bg-[#0c0c0c]">
          PORTABLE AUDIT SUITE &bull; AUTHOR: RAHUL S
        </div>
        <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white uppercase">
          IoT Device Security <span className="text-[#d4af37]">Analyzer</span>
        </h2>
        <p className="text-neutral-400 max-w-xl mx-auto text-xs sm:text-sm leading-relaxed">
          Comprehensive non-destructive vulnerability scanner for connected IoT hardware, smart home protocols, and host system security posture.
        </p>
      </div>

      {/* Main Control Box (Pure Black & Gold Border) */}
      <div
        className="max-w-2xl mx-auto bg-[#0a0a0a] border border-[#262626] p-6 sm:p-8 text-center space-y-6 shadow-2xl relative"
        style={isScanning ? { borderColor: "#d4af37", boxShadow: "0 0 30px rgba(212,175,55,0.15)" } : {}}
      >
        <div className="absolute top-0 left-0 w-2 h-2 bg-[#d4af37]" />
        <div className="absolute top-0 right-0 w-2 h-2 bg-[#d4af37]" />
        <div className="absolute bottom-0 left-0 w-2 h-2 bg-[#d4af37]" />
        <div className="absolute bottom-0 right-0 w-2 h-2 bg-[#d4af37]" />

        {/* Radar Icon / Indicator */}
        <div className="flex justify-center">
          <div className="w-20 h-20 bg-black border border-[#d4af37] flex items-center justify-center relative">
            <span className={`text-2xl text-[#d4af37] ${isScanning ? "animate-spin" : ""}`}>
              &#9670;
            </span>
            {isScanning && (
              <div className="absolute inset-0 border border-[#d4af37] animate-ping opacity-30" />
            )}
          </div>
        </div>

        {/* Status text */}
        <div>
          {isScanning ? (
            <div className="space-y-3">
              <p className="text-[#d4af37] font-mono text-xs uppercase tracking-widest font-bold">
                [ SCAN IN PROGRESS ]
              </p>
              <p className="text-neutral-300 text-xs font-mono transition-all">
                {SCAN_STEPS[stepIdx]}
              </p>
              {/* Progress bar */}
              <div className="w-full bg-[#1c1c1c] h-1.5 overflow-hidden border border-[#333333]">
                <div
                  className="h-full bg-[#d4af37] transition-all duration-700"
                  style={{ width: `${((stepIdx + 1) / SCAN_STEPS.length) * 100}%` }}
                />
              </div>
            </div>
          ) : isError ? (
            <div className="space-y-2">
              <p className="text-red-500 font-mono text-xs font-bold uppercase tracking-wider">
                [ SCAN ERROR ENCOUNTERED ]
              </p>
              <p className="text-neutral-400 text-xs font-mono break-all">{errorMsg}</p>
            </div>
          ) : (
            <div>
              <p className="text-white font-semibold text-sm">Engine Ready for Deployment</p>
              <p className="text-neutral-500 text-xs mt-1 font-mono">
                Click below to begin multi-vector audit of your network and host.
              </p>
            </div>
          )}
        </div>

        {/* Start button */}
        <button
          onClick={onStartScan}
          disabled={isScanning}
          className={`
            ${isScanning ? "opacity-50 cursor-not-allowed bg-[#1c1c1c] text-neutral-500 border border-[#333333]" : "btn-primary"}
            min-w-[220px]
          `}
        >
          {isScanning ? "Auditing Network & Host..." : isError ? "Retry Evaluation" : "Start Security Scan"}
        </button>
      </div>

      {/* Feature Pillars (Boxy) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-2xl mx-auto">
        {[
          { icon: "[01]", title: "IoT & UPnP Discovery", desc: "SSDP broadcast discovery, RTSP cameras, and MQTT protocol inspection" },
          { icon: "[02]", title: "Host Threat Audit", desc: "Inspects temporary binaries, startup run keys, and scheduled tasks" },
          { icon: "[03]", title: "Portable USB Reports", desc: "Exports standardized PDF (ReportLab), HTML, and JSON to USB media" },
        ].map((item) => (
          <div key={item.title} className="bg-[#0a0a0a] border border-[#262626] p-4 text-center space-y-1.5 hover:border-[#d4af37] transition">
            <span className="font-mono text-xs text-[#d4af37] font-bold">{item.icon}</span>
            <p className="font-semibold text-xs text-white uppercase">{item.title}</p>
            <p className="text-neutral-400 text-[11px] font-mono leading-relaxed">{item.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
