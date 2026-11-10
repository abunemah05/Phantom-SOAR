import type { Metadata } from "next";
import "./globals.css";
import AppShell from "@/components/AppShell";

export const metadata: Metadata = {
  title: "Phantom SOAR | Security Orchestration, Automation & Response",
  description: "Security Orchestration, Automation, and Response platform: SIEM alert intake, threat-intel enrichment, policy-guarded playbooks and analyst review.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-100 min-h-screen flex antialiased">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
