"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  ShieldAlert,
  ScrollText,
  Sliders,
  Shield,
  LogOut,
  Users,
  Terminal,
  BarChart3,
  Lock,
  FlaskConical
} from "lucide-react";
import { useAuth } from "@/components/AuthGate";
import { useRuntimeStatus } from "@/components/RuntimeStatusProvider";
import { isAdmin, isSecEngOrAdmin } from "@/lib/roles";

type Access = "all" | "sec_eng" | "admin";

interface NavItem {
  name: string;
  href: string;
  icon: React.ElementType;
  access: Access;
}

const navItems: NavItem[] = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard, access: "all" },
  { name: "Alerts & Cases", href: "/alerts", icon: ShieldAlert, access: "all" },
  { name: "Playbooks", href: "/playbooks", icon: ScrollText, access: "all" },
  { name: "Logs & Telemetry", href: "/logs", icon: Terminal, access: "all" },
  { name: "Admin Reports", href: "/reports", icon: BarChart3, access: "admin" },
  { name: "Configuration", href: "/configuration", icon: Sliders, access: "sec_eng" },
  { name: "Accounts & IAM", href: "/accounts", icon: Users, access: "admin" },
];

const ACCESS_BADGE: Record<Access, string | null> = {
  all: null,
  sec_eng: "Sec Eng",
  admin: "Admin",
};

const TIP_PROVIDERS = ["virustotal", "abuseipdb", "otx", "threatfox"] as const;

export default function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const { status } = useRuntimeStatus();

  const admin = isAdmin(user);
  const secEng = isSecEngOrAdmin(user);

  const hasAccess = (access: Access) =>
    access === "all" || (access === "admin" ? admin : secEng);

  const userInitials = user?.username ? user.username.trim().slice(0, 2).toUpperCase() : "??";

  const integrations = status?.integrations;
  const tipConfigured = integrations ? TIP_PROVIDERS.filter((p) => integrations[p]).length : null;

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
              SecOps Console v2.0
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
          const isActive = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
          const restricted = !hasAccess(item.access);
          const badge = ACCESS_BADGE[item.access];

          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group ${
                isActive
                  ? "bg-blue-600 text-white shadow-md shadow-blue-600/25"
                  : restricted
                  ? "text-slate-500 hover:text-slate-400 hover:bg-slate-900/40 opacity-80"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/80"
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`h-4 w-4 ${
                  isActive
                    ? "text-white"
                    : restricted
                    ? "text-slate-600"
                    : "text-slate-400 group-hover:text-slate-200"
                }`} />
                <span>{item.name}</span>
              </div>
              {badge && (
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full flex items-center gap-1 ${
                  isActive
                    ? "bg-white/20 text-white"
                    : restricted
                    ? "bg-amber-950/40 text-amber-400 border border-amber-800/40"
                    : "bg-blue-950/60 text-blue-400 border border-blue-800/40"
                }`}>
                  {restricted && <Lock className="h-2.5 w-2.5" />}
                  {badge}
                </span>
              )}
            </Link>
          );
        })}

        {/* Live platform status (from /api/configuration/runtime-status) */}
        <div className="pt-6 px-3">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-2">
            Platform Status
          </div>
          <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-3 space-y-2 text-xs">
            {status ? (
              <>
                <div className="flex items-center justify-between text-slate-300">
                  <span className="flex items-center gap-1.5 font-medium">
                    {status.simulation_mode && <FlaskConical className="h-3 w-3 text-fuchsia-400" />}
                    Response connectors
                  </span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                    status.simulation_mode ? "text-fuchsia-300 bg-fuchsia-500/10" : "text-emerald-400 bg-emerald-500/10"
                  }`}>
                    {status.simulation_mode ? "Simulated" : "Live only"}
                  </span>
                </div>
                <div className="flex items-center justify-between text-slate-300">
                  <span className="font-medium">Threat intel</span>
                  <span className="text-[10px] text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded font-mono">
                    {tipConfigured}/{TIP_PROVIDERS.length} configured
                  </span>
                </div>
                <div className="flex items-center justify-between text-slate-300">
                  <span className="font-medium">NVD CVE lookup</span>
                  <span className="text-[10px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded font-mono">
                    {integrations?.nvd ? "API key set" : "No API key"}
                  </span>
                </div>
              </>
            ) : (
              <div className="text-[11px] text-slate-500">Runtime status unavailable.</div>
            )}
            <div className="flex items-center justify-between text-slate-300">
              <span className="font-medium">Your access</span>
              <span className="text-[10px] text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded font-mono">
                {admin ? "Admin" : secEng ? "Sec Eng" : "Analyst"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* User Profile & Logout Footer */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/80 space-y-2">
        <div className="flex items-center justify-between p-2 rounded-xl bg-slate-900 border border-slate-800/80">
          <div className="flex items-center space-x-2.5 overflow-hidden">
            <div className="h-8 w-8 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center font-bold text-xs text-white flex-shrink-0 shadow-sm shadow-blue-500/20">
              {userInitials}
            </div>
            <div className="overflow-hidden">
              <span className="text-xs font-bold text-white block truncate" title={user?.username}>
                {user?.username || "Unknown operator"}
              </span>
              <span className="text-[10px] text-slate-400 block truncate" title={user?.role}>
                {user?.role || ""}
              </span>
            </div>
          </div>

          <button
            onClick={logout}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-950/40 text-slate-400 hover:text-rose-400 transition"
            title="Sign out (revokes this session token)"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
