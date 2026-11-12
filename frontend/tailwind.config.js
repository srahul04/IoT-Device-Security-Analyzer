/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Pure Black & Pure Gold luxury boxy theme
        gold: {
          50:  "#fffdf0",
          100: "#fef9c3",
          200: "#fef08a",
          300: "#fde047",
          400: "#eab308",
          DEFAULT: "#d4af37", // Pure Metallic Gold
          500: "#d4af37",
          600: "#b8860b",     // Dark Goldenrod
          700: "#996515",
          800: "#785110",
          900: "#50360a",
        },
        dark: {
          bg: "#000000",      // Pure Black
          surface: "#0a0a0a", // Off-black container
          card: "#111111",    // Boxy card surface
          border: "#262626",  // Border separator
          muted: "#737373",   // Neutral text
        },
        cyber: {
          bg:       "#000000",   // Pure Black
          surface:  "#0a0a0a",   // Boxy surface
          border:   "#262626",   // Boxy border
          accent:   "#d4af37",   // Pure Gold
          accent2:  "#b8860b",   // Deep Gold
          success:  "#10b981",   // Emerald green
          warning:  "#f59e0b",   // Amber
          danger:   "#ef4444",   // Red
          muted:    "#8a8a8a",   // Slate text
          text:     "#f5f5f5",   // Bright white text
        },
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "'Share Tech Mono'", "ui-monospace", "monospace"],
        sans: ["'Inter'", "'Exo 2'", "ui-sans-serif", "system-ui"],
      },
    },
  },
  plugins: [],
};
