"use client";

import React, { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Power,
  CheckCircle2,
  AlertCircle,
  FlaskConical,
  Plug
} from "lucide-react";
import { api } from "@/lib/api";
import { isAdmin } from "@/lib/roles";
import { useAuth } from "@/components/AuthGate";
import { useRuntimeStatus } from "@/components/RuntimeStatusProvider";

const INTEGRATION_LABELS: Record<string, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  otx: "AlienVault OTX",
  threatfox: "ThreatFox",
  nvd: "NVD",
  wazuh: "Wazuh",
  okta: "Okta",
  jira: "Jira",
  slack: "Slack",
};

export default function Navbar() {
  const { user } = useAuth();
  const { status, error: statusError, refresh } = useRuntimeStatus();
  const [time, setTime] = useState<string>("");
  const [togglingHotl, setTogglingHotl] = useState<boolean>(false);
  const [coreHealthy, setCoreHealthy] = useState<boolean | null>(null);
  const [notice, setNotice] = useState<{ text: string; ok: boolean } | null>(null);

  const canToggleHotl = isAdmin(user);
  const hotlEnabled = status?.hotl_enabled;

  useEffect(() => {
    const updateTime = () => setTime(new Date().toUTCString().slice(17, 25) + " UTC");
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch("/api/health");
        setCoreHealthy(res.ok);
      } catch {
        setCoreHealthy(false);
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 30_000);
    return () => clearInterval(interval);
  }, []);

  const showNotice = (text: string, ok: boolean) => {
    setNotice({ text, ok });
    setTimeout(() => setNotice(null), 4000);
  };

  const handleToggleHotl = async () => {
    if (togglingHotl || hotlEnabled === undefined || !canToggleHotl) return;
    setTogglingHotl(true);
    try {
      const res = await api.toggleHotl(!hotlEnabled);
      await refresh();
      showNotice(
        res.hotl_enabled
          ? "HOTL enabled: HOTL playbooks may contain automatically when there is real evidence and policy allows it."
          : "HOTL paused: every containment action waits for analyst approval.",
        true
      );
    } catch (err: any) {
      showNotice(`Could not change HOTL state: ${err.message || "request failed"}`, false);
    } finally {
      setTogglingHotl(false);
    }
  };

  const integrationEntries = status ? Object.entries(status.integrations) : [];
  const configuredCount = integrationEntries.filter(([, v]) => v).length;
  const integrationTitle = integrationEntries
    .map(([k, v]) => `${INTEGRATION_LABELS[k] || k}: ${v ? "configured" : "not configured"}`)
    .join("\n");

  return (
    <header className="h-16 bg-slate-950/80 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-20 select-none">
      {/* Left: API health and simulation badge */}
      <div className="flex items-center space-x-4">
        <div
          className="flex items-center space-x-2"
          title={coreHealthy === null ? "Checking API..." : coreHealthy ? "SOAR API reachable (/api/health)" : "SOAR API unreachable"}
        >
          <div className={`h-2.5 w-2.5 rounded-full ${
            coreHealthy === null ? "bg-slate-500" : coreHealthy ? "bg-emerald-500" : "bg-rose-500"
          }`} />
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            {coreHealthy === null ? "API // CHECKING" : coreHealthy ? "API // ONLINE" : "API // UNREACHABLE"}
          </span>
        </div>

        {status?.simulation_mode && (
          <div
            className="flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-fuchsia-500/15 border border-fuchsia-500/40 text-fuchsia-300 text-xs font-black tracking-wider"
            title="Simulation mode is ON: response actions against unconfigured connectors are simulated (recorded as SIMULATED, nothing is changed on real systems), and lab threat-intel fixtures are used for documentation IPs and demo IOCs."
          >
            <FlaskConical className="h-3.5 w-3.5" />
            <span>SIMULATION MODE</span>
          </div>
        )}

        {!status && statusError && (
          <div className="hidden lg:flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 text-xs" title={statusError}>
            <AlertCircle className="h-3.5 w-3.5 text-amber-400" />
            <span>Runtime status unavailable</span>
          </div>
        )}
      </div>

      {notice && (
        <div className={`hidden xl:flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900 border text-xs shadow-lg animate-fade-in ${
          notice.ok ? "border-blue-500/40 text-blue-300" : "border-rose-500/40 text-rose-300"
        }`}>
          {notice.ok ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : <AlertCircle className="h-3.5 w-3.5 text-rose-400" />}
          <span>{notice.text}</span>
        </div>
      )}

      {/* Right: clock, integrations, HOTL */}
      <div className="flex items-center space-x-3">
        <div className="font-mono text-xs text-slate-300 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-lg shadow-inner">
          {time || "--:--:-- UTC"}
        </div>

        {status && (
          <div
            className="hidden sm:flex items-center space-x-1.5 bg-slate-900 border border-slate-800 text-slate-300 px-2.5 py-1.5 rounded-lg text-xs font-medium cursor-help"
            title={integrationTitle}
          >
            <Plug className="h-3.5 w-3.5 text-blue-400" />
            <span>{configuredCount}/{integrationEntries.length} integrations configured</span>
          </div>
        )}

        {hotlEnabled === undefined ? (
          <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 text-slate-400 px-3 py-1.5 rounded-lg text-xs font-semibold">
            <ShieldAlert className="h-3.5 w-3.5" />
            <span>HOTL: unknown</span>
          </div>
        ) : (
          <button
            onClick={handleToggleHotl}
            disabled={togglingHotl || !canToggleHotl}
            title={
              (hotlEnabled
                ? "HOTL enabled: HOTL playbooks may contain automatically when there is real evidence (Malicious IOC or Critical telemetry) and policy allows it."
                : "HOTL paused: all containment waits for analyst approval (HITL).") +
              (canToggleHotl ? " Click to toggle." : " Only administrators can change this.")
            }
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold shadow-sm transition-all duration-150 border disabled:cursor-default ${
              hotlEnabled
                ? "bg-blue-600/15 border-blue-500/30 text-blue-300"
                : "bg-amber-500/15 border-amber-500/40 text-amber-300"
            } ${canToggleHotl ? "hover:brightness-125 active:scale-95" : ""} ${togglingHotl ? "opacity-50" : ""}`}
          >
            {hotlEnabled ? <ShieldCheck className="h-3.5 w-3.5 text-blue-400" /> : <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />}
            <span>{hotlEnabled ? "HOTL: Enabled" : "HOTL: Paused (HITL only)"}</span>
            {canToggleHotl && <Power className="h-3.5 w-3.5 opacity-70" />}
          </button>
        )}
      </div>
    </header>
  );
}
