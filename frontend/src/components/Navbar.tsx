"use client";

import React, { useEffect, useState } from "react";
import { 
  Activity, 
  ShieldCheck, 
  ShieldAlert, 
  Cpu, 
  Power, 
  CheckCircle2, 
  AlertCircle,
  Radio
} from "lucide-react";
import { api } from "@/lib/api";

export default function Navbar() {
  const [time, setTime] = useState<string>("");
  const [hotlOnline, setHotlOnline] = useState<boolean>(true);
  const [togglingHotl, setTogglingHotl] = useState<boolean>(false);
  const [coreHealthy, setCoreHealthy] = useState<boolean>(true);
  const [statusNotification, setStatusNotification] = useState<string | null>(null);

  // UTC clock ticker
  useEffect(() => {
    const updateTime = () => {
      setTime(new Date().toUTCString().slice(17, 25) + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Fetch initial HOTL engine status from backend & local cache
  useEffect(() => {
    if (typeof window !== "undefined") {
      const cached = localStorage.getItem("phantom_hotl_enabled");
      if (cached !== null) {
        setHotlOnline(cached === "true");
      }
    }

    const checkStatus = async () => {
      try {
        const res = await api.getHotlStatus();
        setHotlOnline(res.hotl_enabled);
        if (typeof window !== "undefined") {
          localStorage.setItem("phantom_hotl_enabled", String(res.hotl_enabled));
        }
      } catch {
        // Fallback to cached or true
      }
    };

    const checkHealth = async () => {
      try {
        const res = await fetch("/api/health");
        setCoreHealthy(res.ok);
      } catch {
        setCoreHealthy(false);
      }
    };

    checkStatus();
    checkHealth();
  }, []);

  const handleToggleHotl = async () => {
    if (togglingHotl) return;
    setTogglingHotl(true);
    const nextState = !hotlOnline;
    
    // Optimistic UI update
    setHotlOnline(nextState);
    if (typeof window !== "undefined") {
      localStorage.setItem("phantom_hotl_enabled", String(nextState));
      window.dispatchEvent(new CustomEvent("phantom-hotl-change", { detail: { hotl_enabled: nextState } }));
    }

    try {
      const res = await api.toggleHotl(nextState);
      setHotlOnline(res.hotl_enabled);
      if (typeof window !== "undefined") {
        localStorage.setItem("phantom_hotl_enabled", String(res.hotl_enabled));
      }
      setStatusNotification(
        res.hotl_enabled 
          ? "HOTL Autonomous Containment Active: High/Critical alerts will be contained autonomously." 
          : "HOTL Engine Paused: System operating in HITL Standby Mode (Manual analyst approval enforced)."
      );
      setTimeout(() => setStatusNotification(null), 4000);
    } catch {
      // Revert if API fails
      setHotlOnline(!nextState);
      if (typeof window !== "undefined") {
        localStorage.setItem("phantom_hotl_enabled", String(!nextState));
      }
      setStatusNotification("Failed to toggle HOTL state. Please check connection.");
      setTimeout(() => setStatusNotification(null), 3000);
    } finally {
      setTogglingHotl(false);
    }
  };

  return (
    <header className="h-16 bg-slate-950/80 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-20 select-none">
      {/* Left side: Core Status & Framework Indicator */}
      <div className="flex items-center space-x-4">
        <div 
          className="flex items-center space-x-2 cursor-pointer group"
          title={coreHealthy ? "SOAR Core Gateway & Redis Worker Online" : "Connecting to SOAR API Core..."}
        >
          <div className={`h-2.5 w-2.5 rounded-full ${coreHealthy ? "bg-emerald-500 animate-pulse" : "bg-rose-500"}`} />
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider group-hover:text-white transition">
            {coreHealthy ? "SOC AUTOMATION CORE // ACTIVE" : "SOC CORE // RECONNECTING"}
          </span>
        </div>

        <div className="hidden lg:flex items-center space-x-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-400">
          <Cpu className="h-3.5 w-3.5 text-blue-400" />
          <span>
            {hotlOnline ? "SANS PICERL Autonomous Response" : "SANS PICERL: HITL Review Gate Enforced"}
          </span>
        </div>
      </div>

      {/* Ephemeral Feedback Toast */}
      {statusNotification && (
        <div className="hidden xl:flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900 border border-blue-500/40 text-blue-300 text-xs shadow-lg animate-fade-in">
          {hotlOnline ? (
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
          ) : (
            <AlertCircle className="h-3.5 w-3.5 text-amber-400" />
          )}
          <span>{statusNotification}</span>
        </div>
      )}

      {/* Right side: UTC Time, SIEM Fed, and Interactive HOTL Toggle */}
      <div className="flex items-center space-x-3">
        {/* Real-time UTC clock */}
        <div className="font-mono text-xs text-slate-300 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-lg shadow-inner">
          {time || "--:--:-- UTC"}
        </div>

        {/* Wazuh SIEM Pill */}
        <div 
          className="hidden sm:flex items-center space-x-1.5 bg-purple-500/10 border border-purple-500/20 text-purple-300 px-2.5 py-1.5 rounded-lg text-xs font-medium cursor-help"
          title="Wazuh SIEM Ingest Stream: Active via /api/webhooks/wazuh"
        >
          <Activity className="h-3.5 w-3.5 text-purple-400 animate-pulse" />
          <span>Wazuh Agent Fed</span>
        </div>

        {/* INTERACTIVE HOTL Engine Toggle Button */}
        {hotlOnline ? (
          <button
            onClick={handleToggleHotl}
            disabled={togglingHotl}
            title="HOTL Engine Active: Autonomous containment is enabled. Click to Pause (HITL Standby Mode)."
            className="flex items-center space-x-2 bg-blue-600/15 hover:bg-rose-950/40 border border-blue-500/30 hover:border-rose-500/40 text-blue-300 hover:text-rose-300 px-3 py-1.5 rounded-lg text-xs font-semibold shadow-sm transition-all duration-150 active:scale-95 group disabled:opacity-50"
          >
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
            </span>
            <ShieldCheck className="h-3.5 w-3.5 text-blue-400 group-hover:hidden" />
            <Power className="h-3.5 w-3.5 text-rose-400 hidden group-hover:inline-block" />
            <span className="group-hover:hidden">HOTL Engine: Online</span>
            <span className="hidden group-hover:inline-block">Click to Pause HOTL</span>
            <span className="text-[10px] bg-blue-950/80 text-blue-400 px-1 py-0.2 rounded border border-blue-800/50 uppercase font-mono group-hover:hidden">
              ON
            </span>
          </button>
        ) : (
          <button
            onClick={handleToggleHotl}
            disabled={togglingHotl}
            title="HOTL Engine Paused: Autonomous containment is paused. All cases await HITL approval. Click to Re-Enable."
            className="flex items-center space-x-2 bg-amber-500/15 hover:bg-emerald-950/40 border border-amber-500/40 hover:border-emerald-500/40 text-amber-300 hover:text-emerald-300 px-3 py-1.5 rounded-lg text-xs font-semibold shadow-sm transition-all duration-150 active:scale-95 group disabled:opacity-50"
          >
            <span className="h-2 w-2 rounded-full bg-amber-400 group-hover:bg-emerald-400"></span>
            <ShieldAlert className="h-3.5 w-3.5 text-amber-400 group-hover:hidden" />
            <Power className="h-3.5 w-3.5 text-emerald-400 hidden group-hover:inline-block" />
            <span className="group-hover:hidden">HOTL: Standby (Paused)</span>
            <span className="hidden group-hover:inline-block">Click to Enable HOTL</span>
            <span className="text-[10px] bg-amber-950/80 text-amber-400 px-1 py-0.2 rounded border border-amber-800/50 uppercase font-mono group-hover:hidden">
              OFF
            </span>
          </button>
        )}
      </div>
    </header>
  );
}
