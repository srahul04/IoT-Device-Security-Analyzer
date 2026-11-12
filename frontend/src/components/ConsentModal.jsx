// src/components/ConsentModal.jsx
import React, { useState } from "react";

export default function ConsentModal({ onApproved }) {
  const [agreedScope, setAgreedScope] = useState(false);
  const [agreedTelemetry, setAgreedTelemetry] = useState(false);
  const [agreedAuthorization, setAgreedAuthorization] = useState(false);
  const [inputPhrase, setInputPhrase] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPolicyModal, setShowPolicyModal] = useState(false);

  const isFormValid =
    agreedScope &&
    agreedTelemetry &&
    agreedAuthorization &&
    inputPhrase.trim().toUpperCase() === "IAGREE";

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!isFormValid) {
      setError("Please accept all required compliance terms and type 'IAGREE' to proceed.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approval: "IAGREE" }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || "Authorization was declined by the server.");
      onApproved(json.token);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md p-4 overflow-y-auto">
      <div className="relative max-w-2xl w-full bg-[#0d131f] border border-[#1e293b] rounded-xl shadow-2xl p-6 sm:p-8 text-slate-200 my-8">
        {/* Top Header */}
        <div className="flex items-center gap-4 pb-5 border-b border-slate-800">
          <div className="w-12 h-12 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold text-xl">
            &#9921;
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wide text-white">
              IoT Device Security Analyzer (IDSA)
            </h1>
            <p className="text-xs font-mono text-cyan-400">
              Lead Architect &amp; Author: <span className="text-white font-semibold">Rahul S</span> &bull; Portable USB Edition
            </p>
          </div>
        </div>

        {/* Audit Scope Explanation */}
        <div className="mt-5 space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
            Audit Scope &amp; Target Telemetry Overview
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            Prior to execution, IDSA requires formal compliance authorization. This portable suite performs non-destructive local evaluation across the following vectors:
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
            <div className="bg-slate-900/80 border border-slate-800 p-2.5 rounded">
              <span className="text-cyan-400 block font-bold">&#9656; LAN Discovery &amp; UPnP</span>
              SSDP broadcasts, active host ping sweep, common IoT ports (HTTP, RTSP, MQTT).
            </div>
            <div className="bg-slate-900/80 border border-slate-800 p-2.5 rounded">
              <span className="text-cyan-400 block font-bold">&#9656; Service Fingerprinting</span>
              HTTP headers, HTML page titles, RTSP stream accessibility, safe credential checks.
            </div>
            <div className="bg-slate-900/80 border border-slate-800 p-2.5 rounded">
              <span className="text-cyan-400 block font-bold">&#9656; Host Telemetry &amp; Posture</span>
              OS build, disk usage, active users, Windows Firewall profile inspection.
            </div>
            <div className="bg-slate-900/80 border border-slate-800 p-2.5 rounded">
              <span className="text-cyan-400 block font-bold">&#9656; Threat &amp; Persistence Audit</span>
              Suspicious temp binaries, registry Run keys, autorun items, scheduled tasks.
            </div>
          </div>
        </div>

        {/* Terms & Policies Checkbox Group */}
        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-4 space-y-3">
            <label className="flex items-start gap-3 cursor-pointer text-xs leading-relaxed text-slate-300">
              <input
                type="checkbox"
                checked={agreedAuthorization}
                onChange={(e) => setAgreedAuthorization(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
              />
              <span>
                <strong>Ownership &amp; Authorization:</strong> I certify that I own this computer and local network, or possess explicit written consent from the owner to conduct this security analysis.
              </span>
            </label>

            <label className="flex items-start gap-3 cursor-pointer text-xs leading-relaxed text-slate-300">
              <input
                type="checkbox"
                checked={agreedTelemetry}
                onChange={(e) => setAgreedTelemetry(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
              />
              <span>
                <strong>Local Diagnostic Telemetry:</strong> I consent to the analyzer reading local system diagnostics (OS version, active users, process listings, firewall states). <span className="text-cyan-300">This data stays exclusively on this computer and the USB drive. No external servers receive telemetry.</span>
              </span>
            </label>

            <label className="flex items-start gap-3 cursor-pointer text-xs leading-relaxed text-slate-300">
              <input
                type="checkbox"
                checked={agreedScope}
                onChange={(e) => setAgreedScope(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
              />
              <span>
                <strong>Terms of Evaluation:</strong> I agree to the{" "}
                <button
                  type="button"
                  onClick={() => setShowPolicyModal(true)}
                  className="text-cyan-400 underline hover:text-cyan-300"
                >
                  IDSA Terms of Use &amp; Security Policy
                </button>
                , understanding that this tool evaluates vulnerabilities to assist in defensive remediation.
              </span>
            </label>
          </div>

          {/* Typing confirmation */}
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1.5 uppercase tracking-wider">
              Type <span className="text-cyan-400 font-bold">IAGREE</span> to issue session authorization:
            </label>
            <input
              type="text"
              value={inputPhrase}
              onChange={(e) => setInputPhrase(e.target.value)}
              placeholder="IAGREE"
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 font-mono text-center tracking-[0.25em] text-white uppercase outline-none focus:border-cyan-400 transition"
            />
          </div>

          {error && <p className="text-xs font-mono text-red-400">{error}</p>}

          <div className="flex gap-3 pt-2">
            <button
              type="submit"
              disabled={!isFormValid || loading}
              className={`w-full py-3 rounded-lg font-bold text-sm tracking-wide uppercase transition ${
                isFormValid && !loading
                  ? "bg-cyan-500 hover:bg-cyan-400 text-slate-950 cursor-pointer shadow-lg shadow-cyan-500/20"
                  : "bg-slate-800 text-slate-500 cursor-not-allowed opacity-60"
              }`}
            >
              {loading ? "Verifying Token..." : "Authorize & Launch Analyzer"}
            </button>
          </div>
        </form>

        {/* Footer info */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-500">
          <span>Target Architecture: Removable USB Media</span>
          <span>Security Standard: Confidential Audit</span>
        </div>
      </div>

      {/* Terms and Policies Details Modal */}
      {showPolicyModal && (
        <div className="fixed inset-0 z-60 flex items-center justify-center bg-black/90 p-4">
          <div className="bg-[#0b101b] border border-slate-700 rounded-xl max-w-xl w-full p-6 text-slate-300 max-h-[85vh] overflow-y-auto space-y-4 text-xs leading-relaxed">
            <h3 className="text-base font-bold text-white border-b border-slate-800 pb-2">
              IDSA Terms of Use &amp; Privacy Policy
            </h3>
            
            <div>
              <h4 className="font-bold text-cyan-400 uppercase">1. Authorship &amp; Attribution</h4>
              <p className="mt-1 text-slate-400">
                The IoT Device Security Analyzer (IDSA) was engineered and authored by <strong>Rahul S</strong> as an advanced, portable security evaluation system.
              </p>
            </div>

            <div>
              <h4 className="font-bold text-cyan-400 uppercase">2. Strict Local Execution &amp; Zero Cloud Telemetry</h4>
              <p className="mt-1 text-slate-400">
                Are you ok with the tool accessing your system information? <strong>Yes, because no data leaves your machine.</strong> All telemetry—including host OS details, logged-in accounts, network discovery, and security posture findings—is processed in local memory and saved exclusively to the removable USB drive in the <code>MOCK_USB/IDSA_REPORTS</code> folder.
              </p>
            </div>

            <div>
              <h4 className="font-bold text-cyan-400 uppercase">3. Intended Use &amp; Liability</h4>
              <p className="mt-1 text-slate-400">
                This suite is intended solely for authorized audits, vulnerability identification, and defensive security hardening. Scanning third-party infrastructure without explicit consent is strictly prohibited. The author assumes no liability for misuse.
              </p>
            </div>

            <div className="pt-3 border-t border-slate-800 text-right">
              <button
                type="button"
                onClick={() => setShowPolicyModal(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded font-mono text-xs"
              >
                Close &amp; Return
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
