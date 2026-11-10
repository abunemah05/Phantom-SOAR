import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/Sidebar";
import Navbar from "@/components/Navbar";

export const metadata: Metadata = {
  title: "Phantom SOAR | Autonomous Enterprise SecOps Platform",
  description: "Security Orchestration, Automation, and Response platform built for modern SOCs. SANS PICERL & MITRE ATT&CK native.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-100 min-h-screen flex antialiased">
        <Sidebar />
        <div className="flex-1 ml-64 flex flex-col min-h-screen min-w-0">
          <Navbar />
          <main className="flex-1 p-6 lg:p-8 max-w-7xl w-full mx-auto">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
