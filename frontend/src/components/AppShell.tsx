"use client";

import React from "react";
import { usePathname } from "next/navigation";
import AuthGate from "@/components/AuthGate";
import { ConfirmProvider } from "@/components/ConfirmDialog";
import { RuntimeStatusProvider } from "@/components/RuntimeStatusProvider";
import { ToastProvider } from "@/components/Toast";
import Sidebar from "@/components/Sidebar";
import Navbar from "@/components/Navbar";
import { LOGIN_PATH } from "@/lib/api";

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  if (pathname === LOGIN_PATH) {
    return (
      <ToastProvider>
        <ConfirmProvider>
          <AuthGate>
            <main id="main-content" className="flex-1 min-w-0">
              {children}
            </main>
          </AuthGate>
        </ConfirmProvider>
      </ToastProvider>
    );
  }

  return (
    <ToastProvider>
      <ConfirmProvider>
        <AuthGate>
          <RuntimeStatusProvider>
            <a
              href="#main-content"
              className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[90] focus:px-3 focus:py-2 focus:rounded-lg focus:bg-blue-600 focus:text-white focus:text-sm"
            >
              Skip to main content
            </a>
            <Sidebar />
            <div className="flex-1 ml-64 flex flex-col min-h-screen min-w-0">
              <Navbar />
              <main id="main-content" tabIndex={-1} className="flex-1 p-6 lg:p-8 max-w-7xl w-full mx-auto outline-none">
                {children}
              </main>
            </div>
          </RuntimeStatusProvider>
        </AuthGate>
      </ConfirmProvider>
    </ToastProvider>
  );
}
