// src/components/Footer.jsx
import React from "react";

export default function Footer() {
  return (
    <footer className="border-t border-cyber-border bg-cyber-surface/50 mt-auto">
      <div className="container mx-auto px-4 py-3 max-w-7xl flex flex-col sm:flex-row items-center justify-between gap-2">
        <span className="text-xs text-cyber-muted font-mono">
          IDSA v1.0 &mdash; Author: Rahul S &mdash; For authorized use only
        </span>
        <span className="text-xs text-cyber-muted font-mono">
          Backend: <span className="text-cyber-accent">localhost:5000</span>
        </span>
      </div>
    </footer>
  );
}
