"use client";

import React from "react";
import { usePathname } from "next/navigation";
import AuthGate from "@/components/AuthGate";
import { RuntimeStatusProvider } from "@/components/RuntimeStatusProvider";
import Sidebar from "@/components/Sidebar";
import Navbar from "@/components/Navbar";
import { LOGIN_PATH } from "@/lib/api";

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  if (pathname === LOGIN_PATH) {
    return (
      <AuthGate>
        <div className="flex-1 min-w-0">{children}</div>
      </AuthGate>
    );
  }

  return (
    <AuthGate>
      <RuntimeStatusProvider>
        <Sidebar />
        <div className="flex-1 ml-64 flex flex-col min-h-screen min-w-0">
          <Navbar />
          <main className="flex-1 p-6 lg:p-8 max-w-7xl w-full mx-auto">
            {children}
          </main>
        </div>
      </RuntimeStatusProvider>
    </AuthGate>
  );
}
