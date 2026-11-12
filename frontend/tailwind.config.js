/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Cybersecurity dark theme palette
        cyber: {
          bg:       "#0a0e1a",   // near-black background
          surface:  "#111827",   // card background
          border:   "#1f2d44",   // subtle borders
          accent:   "#00d4ff",   // cyan accent (primary actions)
          accent2:  "#7c3aed",   // purple accent (secondary)
          success:  "#10b981",   // green
          warning:  "#f59e0b",   // amber
          danger:   "#ef4444",   // red
          muted:    "#64748b",   // grey text
          text:     "#e2e8f0",   // primary text
        },
      },
      fontFamily: {
        mono: ["'Share Tech Mono'", "ui-monospace", "monospace"],
        sans: ["'Exo 2'", "ui-sans-serif", "system-ui"],
      },
      animation: {
        pulse_slow: "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        scanline:   "scanline 2s linear infinite",
        glow:       "glow 2s ease-in-out infinite alternate",
      },
      keyframes: {
        scanline: {
          "0%":   { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        glow: {
          from: { boxShadow: "0 0 5px #00d4ff44" },
          to:   { boxShadow: "0 0 20px #00d4ff88, 0 0 40px #00d4ff44" },
        },
      },
    },
  },
  plugins: [],
};

