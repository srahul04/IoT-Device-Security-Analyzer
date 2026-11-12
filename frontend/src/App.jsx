// src/App.jsx  –  Root component: manages global state and consent gate
import React, { useState } from "react";
import ConsentModal from "./components/ConsentModal";
import Dashboard    from "./components/Dashboard";
import Results      from "./components/Results";
import Header       from "./components/Header";
import Footer       from "./components/Footer";

/**
 * App state machine:
 *   "consent"  → show ConsentModal
 *   "idle"     → show Dashboard (no results yet)
 *   "scanning" → show Dashboard with loading indicator
 *   "results"  → show Results panel
 *   "error"    → show error message on Dashboard
 */
export default function App() {
  const [phase,       setPhase]       = useState("consent");   // current UI phase
  const [scanData,    setScanData]    = useState(null);         // raw JSON from /api/scan
  const [reportMeta,  setReportMeta]  = useState(null);         // metadata from /api/generate-report
  const [errorMsg,    setErrorMsg]    = useState("");

  // ── Called when user agrees to the consent modal ──────────────────────────
  const handleConsent = () => setPhase("idle");

  // ── Trigger a full scan via the Node backend ──────────────────────────────
  const handleStartScan = async () => {
    setPhase("scanning");
    setErrorMsg("");
    setScanData(null);
    setReportMeta(null);
    try {
      const res  = await fetch("/api/scan", { method: "POST" });
      const json = await res.json();
      if (!json.success) throw new Error(json.error || "Unknown scan error");
      setScanData(json.data);
      setPhase("results");
    } catch (err) {
      setErrorMsg(err.message);
      setPhase("error");
    }
  };

  // ── Trigger report generation and optionally pass current scan data ───────
  const handleGenerateReport = async () => {
    setReportMeta(null);
    try {
      const res = await fetch("/api/generate-report", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ scanData: scanData }),
      });
      const json = await res.json();
      if (!json.success) throw new Error(json.error || "Report generation failed");
      setReportMeta(json.data);
    } catch (err) {
      alert("Report error: " + err.message);
    }
  };

  // ── Reset back to idle (new scan) ─────────────────────────────────────────
  const handleReset = () => {
    setScanData(null);
    setReportMeta(null);
    setErrorMsg("");
    setPhase("idle");
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* ── Global Header ───────────────────────────────────────────────── */}
      <Header />

      {/* ── Main content ────────────────────────────────────────────────── */}
      <main className="flex-1 container mx-auto px-4 py-8 max-w-7xl">
        {/* Consent gate */}
        {phase === "consent" && (
          <ConsentModal onAgree={handleConsent} />
        )}

        {/* Dashboard (idle / scanning / error) */}
        {(phase === "idle" || phase === "scanning" || phase === "error") && (
          <Dashboard
            phase={phase}
            errorMsg={errorMsg}
            onStartScan={handleStartScan}
          />
        )}

        {/* Results panel */}
        {phase === "results" && scanData && (
          <Results
            data={scanData}
            reportMeta={reportMeta}
            onGenerateReport={handleGenerateReport}
            onNewScan={handleReset}
          />
        )}
      </main>

      <Footer />
    </div>
  );
}

