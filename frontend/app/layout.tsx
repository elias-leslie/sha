import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";

import PwaRegister from "../components/pwa-register";
import "./globals.css";

export const metadata: Metadata = {
  title: "SHA | Security Control Plane",
  description: "Endpoint Posture, Compliance & Remote Hardening Control Plane",
  manifest: "/manifest.json",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "SHA Control",
  },
  icons: {
    icon: "/icon.svg",
    apple: "/icons/icon-192x192.png",
    shortcut: "/icon.svg",
  },
};

export const viewport: Viewport = {
  themeColor: "#0b0f19",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <head>
        <link href="/manifest.json" rel="manifest" />
        <meta content="#0b0f19" name="theme-color" />
        <meta content="yes" name="mobile-web-app-capable" />
      </head>
      <body>
        <PwaRegister />
        {children}
      </body>
    </html>
  );
}
