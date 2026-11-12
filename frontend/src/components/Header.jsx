// src/components/Header.jsx  –  Top navigation bar
import React from "react";

export default function Header() {
  return (
    <header className="border-b border-cyber-border bg-cyber-surface/80 backdrop-blur-sm sticky top-0 z-40">
      <div className="container mx-auto px-4 py-3 max-w-7xl flex items-center justify-between">
        {/* Logo & title */}
        <div className="flex items-center gap-3">
          {/* Animated shield icon */}
          <div className="relative">
            <div className="w-9 h-9 rounded-lg bg-cyber-accent/10 border border-cyber-accent/40 flex items-center justify-center animate-pulse_slow">
              <svg viewBox="0 0 24 24" className="w-5 h-5 fill-cyber-accent" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
              </svg>
            </div>
            {/* Pulsing ring */}
            <div className="absolute inset-0 rounded-lg border border-cyber-accent/20 animate-ping" />
          </div>
          <div>
            <span className="text-lg font-bold tracking-wider text-cyber-text">
              <span className="cyber-accent">IDSA</span>
            </span>
            <p className="text-xs text-cyber-muted font-mono leading-none">
              IoT Device Security Analyzer
            </p>
          </div>
        </div>

        {/* Status pill */}
        <div className="flex items-center gap-2 text-xs font-mono text-cyber-muted">
          <span className="w-2 h-2 rounded-full bg-cyber-success animate-pulse" />
          <span>SYSTEM ONLINE</span>
        </div>
      </div>
    </header>
  );
}

