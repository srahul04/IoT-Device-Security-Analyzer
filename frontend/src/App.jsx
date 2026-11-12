// src/App.jsx
// Root component. Manages global state and the approval gate.
import React, { useState } from "react";
import ConsentModal from "./components/ConsentModal";
import Dashboard    from "./components/Dashboard";
import Results      from "./components/Results";
import Header       from "./components/Header";
import Footer       from "./components/Footer";

// API helper with JWT attached
async function apiFetch(path, options = {}) {
  const token = sessionStorage.getItem("IDSA_TOKEN");
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(path, { ...options, headers });
  return res;
}

export default function App() {
  const [phase,      setPhase]      = useState("consent");
  const [scanData,   setScanData]   = useState(null);
  const [reportMeta, setReportMeta] = useState(null);
  const [errorMsg,   setErrorMsg]   = useState("");

  // Called after user types IAGREE and backend issues a token
  const handleConsent = (token) => {
    sessionStorage.setItem("IDSA_TOKEN", token);
    setPhase("idle");
  };

  const handleStartScan = async () => {
    setPhase("scanning");
    setErrorMsg("");
    setScanData(null);
    setReportMeta(null);
    try {
      const res  = await apiFetch("/api/scan", { method: "POST" });
      const json = await res.json();
      if (!json.success) throw new Error(json.error || "Scan failed");
      setScanData(json.data);
      setPhase("results");
    } catch (err) {
      setErrorMsg(err.message);
      setPhase("error");
    }
  };

  const handleGenerateReport = async () => {
    setReportMeta(null);
    try {
      const res  = await apiFetch("/api/generate-report", {
        method: "POST",
        body:   JSON.stringify({ scanData }),
      });
      const json = await res.json();
      if (!json.success) throw new Error(json.error || "Report generation failed");
      setReportMeta(json.data);
    } catch (err) {
      alert("Report error: " + err.message);
    }
  };

  const handleReset = () => {
    setScanData(null);
    setReportMeta(null);
    setErrorMsg("");
    setPhase("idle");
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Header />

      <main className="flex-1 container mx-auto px-4 py-8 max-w-7xl">
        {phase === "consent" && (
          <ConsentModal onApproved={handleConsent} />
        )}

        {(phase === "idle" || phase === "scanning" || phase === "error") && (
          <Dashboard
            phase={phase}
            errorMsg={errorMsg}
            onStartScan={handleStartScan}
          />
        )}

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
