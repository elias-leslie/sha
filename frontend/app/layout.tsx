import type { Metadata } from "next";
import { Azeret_Mono, IBM_Plex_Sans } from "next/font/google";
import type { ReactNode } from "react";

import "./globals.css";

const bodyFont = IBM_Plex_Sans({
  subsets: ["latin"],
  variable: "--font-body",
  weight: ["400", "500", "600", "700"],
});

const displayFont = Azeret_Mono({
  subsets: ["latin"],
  variable: "--font-display",
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "SHA | Security Control Plane",
  description: "Dark amber operator workspace for security hardening automation, approvals, and installer orchestration.",
  icons: {
    icon: "/icon.svg",
    shortcut: "/icon.svg",
  },
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html className={`${bodyFont.variable} ${displayFont.variable}`} lang="en">
      <body>{children}</body>
    </html>
  );
}
