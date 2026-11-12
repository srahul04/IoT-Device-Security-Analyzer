// src/components/ConsentModal.jsx
import React, { useState } from "react";

export default function ConsentModal({ onApproved }) {
  const [agreed, setAgreed] = useState(false);
  const [inputPhrase, setInputPhrase] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPolicyPopup, setShowPolicyPopup] = useState(false);

  const isFormValid = agreed && inputPhrase.trim().toUpperCase() === "IAGREE";

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!isFormValid) {
      setError("Please check the Terms & Policies box and type 'IAGREE' to proceed.");
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/95 p-4">
      {/* Boxy Pure Black & Gold Container */}
      <div className="relative max-w-xl w-full bg-[#0a0a0a] border-2 border-[#d4af37] p-6 sm:p-8 text-neutral-200 shadow-2xl">
        {/* Top Gold Bar */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-[#d4af37]" />

        {/* Header with Project Details & Author */}
        <div className="pb-4 border-b border-[#262626]">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono tracking-widest text-[#d4af37] uppercase">
              PORTABLE USB EDITION
            </span>
            <span className="text-[11px] font-mono text-neutral-500">
              AUDIT PROTOCOL v2.0
            </span>
          </div>

          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white mt-1">
            IoT Device Security Analyzer <span className="text-[#d4af37]">(IDSA)</span>
          </h1>

          <p className="text-xs font-mono text-neutral-400 mt-1">
            Author &amp; Lead Architect: <span className="text-[#d4af37] font-semibold">Rahul S</span>
          </p>
        </div>

        {/* Project Context & Diagnostic Explanation Paragraph */}
        <div className="mt-4 space-y-2.5 text-xs text-neutral-300 leading-relaxed">
          <p>
            The <strong>IoT Device Security Analyzer</strong> is an automated cybersecurity assessment framework engineered specifically to operate directly from removable USB media. It inspects local network topology, discovers connected IoT nodes via SSDP/UPnP, fingerprints open services, tests common factory credentials, and evaluates host persistence mechanisms and security policies.
          </p>
          <p className="text-neutral-400">
            <strong>Are you ok with sharing your system information?</strong> For security reasons regarding your computer only, this analyzer collects hardware telemetry, OS configuration, active network routes, and local security posture. <span className="text-[#d4af37]">All diagnostic data remains strictly inside local computer memory and is saved exclusively to the connected USB drive.</span> No external servers or cloud services receive your data.
          </p>
        </div>

        {/* Form with standard checkbox + IAGREE */}
        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          {/* Single Standard Terms & Policies Checkbox with Popup link */}
          <div className="bg-[#111111] border border-[#262626] p-3.5">
            <label className="flex items-start gap-3 cursor-pointer text-xs text-neutral-300">
              <input
                type="checkbox"
                checked={agreed}
                onChange={(e) => setAgreed(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded-none border border-[#d4af37] bg-black accent-[#d4af37] cursor-pointer"
              />
              <span className="leading-normal">
                I have read and agree to the{" "}
                <button
                  type="button"
                  onClick={() => setShowPolicyPopup(true)}
                  className="text-[#d4af37] underline font-semibold hover:text-[#fef08a]"
                >
                  Terms and Policies
                </button>
                , and I authorize this local security audit on my computer and connected network.
              </span>
            </label>
          </div>

          {/* Passphrase Input */}
          <div>
            <label className="block text-[11px] font-mono text-neutral-400 uppercase tracking-widest mb-1.5">
              Type <span className="text-[#d4af37] font-bold">IAGREE</span> to verify consent:
            </label>
            <input
              type="text"
              value={inputPhrase}
              onChange={(e) => setInputPhrase(e.target.value)}
              placeholder="IAGREE"
              className="w-full bg-black border border-[#333333] rounded-none px-4 py-2.5 font-mono text-center tracking-[0.25em] text-[#d4af37] uppercase text-sm outline-none focus:border-[#d4af37] transition"
            />
          </div>

          {error && (
            <p className="text-xs font-mono text-red-400 bg-red-950/40 border border-red-800 p-2 text-center">
              {error}
            </p>
          )}

          {/* Authorize Button */}
          <button
            type="submit"
            disabled={!isFormValid || loading}
            className={`w-full py-3 rounded-none font-bold text-xs uppercase tracking-widest transition ${
              isFormValid && !loading
                ? "bg-[#d4af37] hover:bg-[#b8860b] text-black cursor-pointer shadow-[0_0_15px_rgba(212,175,55,0.3)]"
                : "bg-[#1c1c1c] text-[#555555] border border-[#2e2e2e] cursor-not-allowed"
            }`}
          >
            {loading ? "Issuing Authorization Token..." : "Authorize & Proceed"}
          </button>
        </form>

        <div className="mt-4 pt-3 border-t border-[#1f1f1f] flex justify-between items-center text-[10px] font-mono text-neutral-500">
          <span>Target Architecture: Removable USB Media</span>
          <span>Author: Rahul S</span>
        </div>
      </div>

      {/* Separate Terms & Policies Popup */}
      {showPolicyPopup && (
        <div className="fixed inset-0 z-60 flex items-center justify-center bg-black/90 p-4">
          <div className="bg-[#0c0c0c] border-2 border-[#d4af37] max-w-lg w-full p-6 text-neutral-300 shadow-2xl space-y-4 text-xs leading-relaxed max-h-[85vh] overflow-y-auto">
            <div className="flex justify-between items-center border-b border-[#262626] pb-3">
              <h2 className="text-sm font-bold uppercase tracking-wider text-[#d4af37]">
                Terms &amp; Security Policies
              </h2>
              <button
                type="button"
                onClick={() => setShowPolicyPopup(false)}
                className="text-neutral-400 hover:text-white font-mono text-base px-1"
              >
                &times;
              </button>
            </div>

            <div>
              <h3 className="font-bold text-white uppercase text-[11px] mb-1">
                1. Project Identity &amp; Authorship
              </h3>
              <p className="text-neutral-400">
                The IoT Device Security Analyzer (IDSA) is developed and maintained by <strong>Rahul S</strong>. It is created to provide automated, reliable, and rigorous auditing of local networks, smart peripherals, and host machines.
              </p>
            </div>

            <div>
              <h3 className="font-bold text-white uppercase text-[11px] mb-1">
                2. Privacy &amp; Diagnostic Telemetry Protection
              </h3>
              <p className="text-neutral-400">
                Are you ok with sharing your system information? <strong>Yes, because your data never leaves your environment.</strong> All system data (operating system build, CPU architecture, active accounts, process listings, firewall status, and discovered IoT nodes) is inspected for the sole purpose of identifying security vulnerabilities on your machine. All outputs are written exclusively to the local drive path (<code>MOCK_USB/IDSA_REPORTS</code>).
              </p>
            </div>

            <div>
              <h3 className="font-bold text-white uppercase text-[11px] mb-1">
                3. Authorized Evaluation Notice
              </h3>
              <p className="text-neutral-400">
                This tool is intended for defensive security assessments and authorized educational evaluations. By executing the analyzer, you confirm that you have explicit permission to evaluate the host computer and connected network.
              </p>
            </div>

            <div className="pt-3 border-t border-[#262626] text-right">
              <button
                type="button"
                onClick={() => setShowPolicyPopup(false)}
                className="px-4 py-2 bg-[#d4af37] hover:bg-[#b8860b] text-black font-bold uppercase text-[11px] tracking-wider rounded-none"
              >
                I Understand &amp; Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
