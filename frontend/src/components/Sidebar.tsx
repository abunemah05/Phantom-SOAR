"use client";

import React, { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { 
  LayoutDashboard, 
  ShieldAlert, 
  ScrollText, 
  Sliders, 
  Shield, 
  Radio, 
  LogOut, 
  Users, 
  Terminal, 
  BarChart3,
  Lock,
  UserCheck
} from "lucide-react";
import { User } from "@/lib/types";
import { getStoredUser, clearAuth, subscribeToAuth } from "@/lib/auth";
import { syncCurrentUser } from "@/lib/api";

interface NavItem {
  name: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
  adminOnly?: boolean;
}

const navItems: NavItem[] = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "Alerts & Cases", href: "/alerts", icon: ShieldAlert },
  { name: "Playbooks", href: "/playbooks", icon: ScrollText },
  { name: "Logs & Telemetry", href: "/logs", icon: Terminal },
  { name: "Admin Reports", href: "/reports", icon: BarChart3, badge: "Admin", adminOnly: true },
  { name: "Configuration", href: "/configuration", icon: Sliders },
  { name: "Accounts & IAM", href: "/accounts", icon: Users, badge: "Admin", adminOnly: true },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [mounted, setMounted] = useState<boolean>(false);

  // Sync user state from local storage and backend
  const refreshUser = useCallback(async () => {
    // 1. Immediate sync from local storage
    const stored = getStoredUser();
    if (stored) {
      setCurrentUser(stored);
    } else {
      setCurrentUser(null);
    }

    // 2. Reconcile with live backend token verification if not on login page
    if (pathname !== "/login") {
      try {
        const liveUser = await syncCurrentUser();
        if (liveUser) {
          setCurrentUser(liveUser);
        } else if (!stored) {
          setCurrentUser(null);
        }
      } catch {
        // Fallback to local storage if network glitch
      }
    }
  }, [pathname]);

  useEffect(() => {
    setMounted(true);
    refreshUser();

    // Listen for custom auth events and storage modifications
    const unsubscribe = subscribeToAuth((updatedUser) => {
      setCurrentUser(updatedUser);
    });

    return () => {
      unsubscribe();
    };
  }, [refreshUser]);

  // Re-verify whenever pathname changes (e.g., returning from /login)
  useEffect(() => {
    if (mounted && pathname !== "/login") {
      refreshUser();
    }
  }, [pathname, mounted, refreshUser]);

  const handleLogout = () => {
    clearAuth();
    setCurrentUser(null);
    router.push("/login");
  };

  if (pathname === "/login") return null;

  const isAdmin = Boolean(
    currentUser?.role && (
      currentUser.role.toLowerCase().includes("admin") || 
      currentUser.role.toLowerCase().includes("lead")
    )
  );

  const userInitials = currentUser?.username
    ? currentUser.username.trim().slice(0, 2).toUpperCase()
    : "??";

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 flex flex-col h-screen fixed left-0 top-0 select-none z-30">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center shadow-lg shadow-blue-500/20">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-1.5">
              <span className="font-extrabold text-base tracking-wider text-white">PHANTOM</span>
              <span className="text-xs px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 font-bold border border-blue-500/30">
                SOAR
              </span>
            </div>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-semibold mt-0.5">
              Enterprise SecOps v2.0
            </p>
          </div>
        </div>
      </div>

      {/* Main Navigation */}
      <div className="flex-1 py-6 px-3 space-y-1.5 overflow-y-auto">
        <div className="px-3 pb-2 text-[11px] font-bold text-slate-500 uppercase tracking-wider">
          Operations Core
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = item.href === "/" 
            ? pathname === "/" 
            : pathname.startsWith(item.href) || (item.href === "/configuration" && pathname.startsWith("/configration"));

          const isRestrictedForAnalyst = item.adminOnly && !isAdmin;

          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group ${
                isActive
                  ? "bg-blue-600 text-white shadow-md shadow-blue-600/25"
                  : isRestrictedForAnalyst
                  ? "text-slate-500 hover:text-slate-400 hover:bg-slate-900/40 opacity-80"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/80"
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`h-4 w-4 ${
                  isActive 
                    ? "text-white" 
                    : isRestrictedForAnalyst 
                    ? "text-slate-600" 
                    : "text-slate-400 group-hover:text-slate-200"
                }`} />
                <span>{item.name}</span>
              </div>
              {item.badge && (
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full flex items-center gap-1 ${
                  isActive 
                    ? "bg-white/20 text-white" 
                    : isRestrictedForAnalyst
                    ? "bg-amber-950/40 text-amber-400 border border-amber-800/40"
                    : "bg-blue-950/60 text-blue-400 border border-blue-800/40"
                }`}>
                  {isRestrictedForAnalyst && <Lock className="h-2.5 w-2.5" />}
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}

        {/* Frameworks & Architecture Standards */}
        <div className="pt-6 px-3">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-2">
            Standards & Frameworks
          </div>
          <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-3 space-y-2 text-xs">
            <div className="flex items-center justify-between text-slate-300">
              <span className="flex items-center gap-1.5 font-medium">
                <Radio className="h-3 w-3 text-emerald-400 animate-pulse" />
                NIST SP 800-63B
              </span>
              <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded font-mono">Enforced</span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span className="font-medium">Multi-TIP Engine</span>
              <span className="text-[10px] text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded font-mono">3 TIPs</span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span className="font-medium">NVD CVE Intel</span>
              <span className="text-[10px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded font-mono">API 2.0</span>
            </div>
            <div className="flex items-center justify-between text-slate-300">
              <span className="font-medium">RBAC Security</span>
              <span className="text-[10px] text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded font-mono">
                {isAdmin ? "Admin Role" : "Analyst Role"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* User Profile & Logout Footer */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/80 space-y-2">
        <div className="flex items-center justify-between p-2 rounded-xl bg-slate-900 border border-slate-800/80">
          {currentUser ? (
            <div className="flex items-center space-x-2.5 overflow-hidden">
              <div className="h-8 w-8 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center font-bold text-xs text-white flex-shrink-0 shadow-sm shadow-blue-500/20">
                {userInitials}
              </div>
              <div className="overflow-hidden">
                <span className="text-xs font-bold text-white block truncate" title={currentUser.username}>
                  {currentUser.username}
                </span>
                <span className="text-[10px] text-slate-400 block truncate" title={currentUser.role}>
                  {currentUser.role}
                </span>
              </div>
            </div>
          ) : (
            <Link href="/login" className="flex items-center space-x-2.5 overflow-hidden group">
              <div className="h-8 w-8 rounded-lg bg-slate-800 flex items-center justify-center font-bold text-xs text-slate-400 flex-shrink-0 group-hover:bg-blue-600 group-hover:text-white transition">
                <UserCheck className="h-4 w-4" />
              </div>
              <div className="overflow-hidden">
                <span className="text-xs font-bold text-slate-300 group-hover:text-blue-400 block truncate">
                  Unauthenticated
                </span>
                <span className="text-[10px] text-slate-500 block truncate">
                  Click to Sign In
                </span>
              </div>
            </Link>
          )}

          {currentUser && (
            <button
              onClick={handleLogout}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-950/40 text-slate-400 hover:text-rose-400 transition"
              title="Log Out of SOC Session"
            >
              <LogOut className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>
    </aside>
  );
}
