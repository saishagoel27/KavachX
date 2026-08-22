import type { Metadata, Viewport } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "KavachX — Find it. Shield it. Repair it. Prove it.",
    template: "%s · KavachX",
  },
  description:
    "Graph-grounded autonomous cyber-reasoning with proof-carrying repair. KavachX reconstructs " +
    "the behavioural contract of software, validates vulnerabilities against executable evidence, " +
    "repairs root causes and produces proof-carrying security certificates.",
  applicationName: "KavachX",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: "#0b0d0e",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-screen bg-background" suppressHydrationWarning>
        <div className="noise" aria-hidden="true" />
        {children}
      </body>
    </html>
  );
}