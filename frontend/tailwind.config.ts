import type { Config } from "tailwindcss";

/**
 * KavachX design tokens.
 *
 * The palette comes from the product design system: a near-black ground, layered surfaces, a
 * single cyan accent for the system's own voice, and semantic colours that carry meaning rather
 * than decoration — amber for "unproved / blocked", red for "refuted", green for "verified".
 * That mapping is load-bearing in this product: a reader should be able to tell a refuted patch
 * from a verified one without reading a word.
 */
const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "#0b0d0e",
        surface: {
          DEFAULT: "#121414",
          lowest: "#0d0e0f",
          low: "#1b1c1c",
          container: "#1f2020",
          high: "#292a2a",
          highest: "#343535",
          bright: "#383939",
        },
        border: {
          DEFAULT: "rgba(255,255,255,0.09)",
          strong: "rgba(255,255,255,0.16)",
          variant: "#3a494b",
        },
        foreground: {
          DEFAULT: "#e3e2e2",
          muted: "#b9cacb",
          subtle: "#849495",
          faint: "#5e6b6c",
        },
        accent: {
          DEFAULT: "#00f2ff",
          dim: "#00dbe7",
          deep: "#006a71",
          on: "#00363a",
          fixed: "#74f5ff",
        },
        verified: { DEFAULT: "#3ddc84", dim: "#1f8f52", on: "#00210f" },
        refuted: { DEFAULT: "#ff6b5e", dim: "#93000a", on: "#ffdad6" },
        warn: { DEFAULT: "#f5b642", dim: "#7a5300", on: "#2a1c00" },
        info: { DEFAULT: "#7ab8ff", dim: "#1f4f8f" },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "Inter", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "JetBrains Mono", "ui-monospace", "monospace"],
      },
      fontSize: {
        "mono-label": ["11px", { lineHeight: "16px", letterSpacing: "0.08em", fontWeight: "700" }],
        "mono-data": ["12.5px", { lineHeight: "18px", letterSpacing: "0em", fontWeight: "500" }],
        "headline-lg": ["32px", { lineHeight: "38px", letterSpacing: "-0.02em", fontWeight: "700" }],
        "headline-md": ["23px", { lineHeight: "30px", letterSpacing: "-0.015em", fontWeight: "600" }],
        "headline-sm": ["17px", { lineHeight: "24px", letterSpacing: "-0.01em", fontWeight: "600" }],
        body: ["14px", { lineHeight: "21px" }],
        small: ["12.5px", { lineHeight: "18px" }],
      },
      borderRadius: { DEFAULT: "3px", md: "5px", lg: "8px", xl: "12px" },
      spacing: { 18: "4.5rem", 22: "5.5rem" },
      boxShadow: {
        glow: "0 0 0 1px rgba(0,242,255,0.35), 0 0 24px -6px rgba(0,242,255,0.35)",
        panel: "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 8px 32px -16px rgba(0,0,0,0.9)",
        "glow-refuted": "0 0 0 1px rgba(255,107,94,0.5), 0 0 32px -8px rgba(255,107,94,0.45)",
        "glow-verified": "0 0 0 1px rgba(61,220,132,0.4), 0 0 28px -10px rgba(61,220,132,0.35)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-ring": {
          "0%": { boxShadow: "0 0 0 0 rgba(0,242,255,0.45)" },
          "70%": { boxShadow: "0 0 0 8px rgba(0,242,255,0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(0,242,255,0)" },
        },
        "scan-line": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(400%)" },
        },
        marquee: { "0%": { opacity: "0.35" }, "50%": { opacity: "1" }, "100%": { opacity: "0.35" } },
      },
      animation: {
        "fade-up": "fade-up 0.5s cubic-bezier(0.16,1,0.3,1) both",
        "pulse-ring": "pulse-ring 2s cubic-bezier(0.4,0,0.6,1) infinite",
        "scan-line": "scan-line 2.4s linear infinite",
        marquee: "marquee 2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};

export default config;
