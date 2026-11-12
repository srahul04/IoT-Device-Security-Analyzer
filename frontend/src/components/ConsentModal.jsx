// src/components/ConsentModal.jsx
//
// Renders a full-screen consent gate.
// User MUST type "IAGREE" (case-insensitive) before proceeding.
import React, { useState } from "react";

export default function ConsentModal({ onAgree }) {
  const [input,   setInput]   = useState("");
  const [shaking, setShaking] = useState(false); // animation for wrong input

  const REQUIRED_PHRASE = "IAGREE";
  const isMatch = input.trim().toUpperCase() === REQUIRED_PHRASE;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (isMatch) {
      onAgree();
    } else {
      // Shake the modal on wrong input
      setShaking(true);
      setTimeout(() => setShaking(false), 600);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-cyber-bg/95 backdrop-blur-sm p-4">
      {/* Grid overlay */}
      <div
        className="absolute inset-0 opacity-5 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(#00d4ff22 1px, transparent 1px), linear-gradient(90deg, #00d4ff22 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      {/* Modal card */}
      <div
        className={`
          relative cyber-card max-w-lg w-full border-cyber-accent/30
          transition-transform duration-150
          ${shaking ? "animate-[shake_0.5s_ease-in-out]" : ""}
        `}
        style={{
          boxShadow: "0 0 60px #00d4ff22, 0 0 120px #00d4ff11",
        }}
      >
        {/* Top accent line */}
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-cyber-accent to-transparent rounded-t-xl" />

        {/* Shield icon */}
        <div className="flex justify-center mb-5">
          <div className="relative w-20 h-20 rounded-2xl bg-cyber-accent/10 border border-cyber-accent/30 flex items-center justify-center">
            <svg viewBox="0 0 24 24" className="w-10 h-10 fill-cyber-accent" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
            </svg>
            <div className="absolute inset-0 rounded-2xl border border-cyber-accent/20 animate-ping" />
          </div>
        </div>

        {/* Title */}
        <h1 className="text-2xl font-bold text-center text-cyber-text tracking-widest uppercase mb-1">
          Authorization Required
        </h1>
        <p className="text-center text-cyber-accent font-mono text-sm mb-6 tracking-wider">
          IoT Device Security Analyzer
        </p>

        {/* Disclaimer */}
        <div className="bg-cyber-bg rounded-lg border border-cyber-border p-4 mb-6 text-sm text-cyber-muted leading-relaxed">
          <p className="text-cyber-warning font-semibold mb-2">⚠ LEGAL DISCLAIMER</p>
          <p>
            This tool is intended for <span className="text-cyber-text font-semibold">educational and
            authorized security testing purposes only</span>. You must have explicit
            written permission to scan any network or device you do not own.
          </p>
          <p className="mt-2">
            Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA)
            and similar laws. The developers assume <span className="text-cyber-text font-semibold">no liability</span> for
            any misuse or damage caused by this software.
          </p>
        </div>

        {/* Consent input */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-cyber-muted mb-2 uppercase tracking-widest">
              Type&nbsp;<span className="text-cyber-accent">IAGREE</span>&nbsp;to confirm you have authorization to proceed:
            </label>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="IAGREE"
              autoFocus
              className={`
                w-full bg-cyber-bg border rounded-lg px-4 py-3
                font-mono text-lg text-center tracking-[0.3em] uppercase
                outline-none transition-all duration-200
                placeholder:text-cyber-border placeholder:tracking-normal placeholder:text-sm
                ${isMatch
                  ? "border-cyber-success text-cyber-success"
                  : "border-cyber-border text-cyber-text focus:border-cyber-accent"
                }
              `}
            />
          </div>

          <button
            type="submit"
            disabled={!isMatch}
            className={`
              w-full py-3 rounded-lg font-bold tracking-widest uppercase text-sm
              transition-all duration-200
              ${isMatch
                ? "btn-primary cursor-pointer"
                : "bg-cyber-border text-cyber-muted cursor-not-allowed opacity-50"
              }
            `}
          >
            {isMatch ? "✓ Authorize & Proceed" : "Enter Passphrase to Continue"}
          </button>
        </form>

        {/* Bottom warning */}
        <p className="text-center text-xs text-cyber-muted mt-4 font-mono">
          By proceeding you accept all legal and ethical responsibility.
        </p>
      </div>

      {/* Keyframe for shake animation (injected inline) */}
      <style>{`
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          20% { transform: translateX(-8px); }
          40% { transform: translateX(8px); }
          60% { transform: translateX(-6px); }
          80% { transform: translateX(6px); }
        }
      `}</style>
    </div>
  );
}

