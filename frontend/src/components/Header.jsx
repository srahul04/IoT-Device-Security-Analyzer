// src/components/Header.jsx
import React from "react";

export default function Header() {
  return (
    <header className="border-b border-[#262626] bg-[#000000] sticky top-0 z-40">
      <div className="container mx-auto px-4 py-3 max-w-7xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          {/* Pure Gold Boxy Security Shield Icon */}
          <div className="w-9 h-9 bg-black border border-[#d4af37] flex items-center justify-center text-[#d4af37] shadow-[0_0_10px_rgba(212,175,55,0.2)]">
            <svg
              className="w-5 h-5 fill-[#d4af37]"
              viewBox="0 0 24 24"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.54-3.15 8.78-7 9.88-3.85-1.1-7-5.34-7-9.88V6.3l7-3.12zm-1 5.82v6h2v-6h-2zm0 8v2h2v-2h-2z" />
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-bold tracking-wider text-white">
                IDSA <span className="text-[#d4af37]">PRO</span>
              </span>
              <span className="text-[10px] font-mono uppercase bg-[#141414] border border-[#333333] px-1.5 py-0.5 text-neutral-400">
                Author: Rahul S
              </span>
            </div>
            <p className="text-[11px] text-neutral-500 font-mono leading-none mt-0.5">
              IoT Device Security Analyzer &bull; Portable Edition
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-[#d4af37] bg-[#0c0c0c] border border-[#262626] px-3 py-1">
          <span className="w-2 h-2 bg-[#d4af37] animate-pulse" />
          <span>SYSTEM SECURE</span>
        </div>
      </div>
    </header>
  );
}
