// src/components/Footer.jsx
import React from "react";

export default function Footer() {
  return (
    <footer className="border-t border-[#262626] bg-[#000000] mt-auto">
      <div className="container mx-auto px-4 py-3 max-w-7xl flex flex-col sm:flex-row items-center justify-between gap-2 text-xs font-mono text-neutral-500">
        <span>
          IDSA v2.0 &bull; Author: <strong className="text-[#d4af37]">Rahul S</strong> &bull; Removable USB Execution Architecture
        </span>
        <span>
          Target Host: <span className="text-white">localhost:5000</span>
        </span>
      </div>
    </footer>
  );
}
