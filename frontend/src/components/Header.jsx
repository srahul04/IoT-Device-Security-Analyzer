// src/components/Header.jsx
import React from "react";

export default function Header() {
  return (
    <header className="border-b border-[#262626] bg-[#000000] sticky top-0 z-40">
      <div className="container mx-auto px-4 py-3 max-w-7xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-[#0a0a0a] border border-[#d4af37] flex items-center justify-center text-[#d4af37] font-bold text-sm">
            &#9632;
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
            <p className="text-[11px] text-neutral-500 font-mono leading-none">
              IoT Device Security Analyzer &bull; Portable Edition
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-[#d4af37] bg-[#0c0c0c] border border-[#262626] px-3 py-1">
          <span className="w-2 h-2 bg-[#d4af37] animate-pulse" />
          <span>SYSTEM READY</span>
        </div>
      </div>
    </header>
  );
}
