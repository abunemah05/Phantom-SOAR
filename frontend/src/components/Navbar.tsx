"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ShieldCheck, ShieldAlert, Power, AlertCircle, FlaskConical, Plug } from "lucide-react";
import { api } from "@/lib/api";
import { describeError, errorBlockers } from "@/lib/errors";
import { isAdmin, isSecEngOrAdmin } from "@/lib/roles";
import { usePolling } from "@/hooks/usePolling";
import { useAuth } from "@/components/AuthGate";
import { useConfirm } from "@/components/ConfirmDialog";
import { useRuntimeStatus } from "@/components/RuntimeStatusProvider";
import { useToast } from "@/components/Toast";

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
  const confirm = useConfirm();
  const toast = useToast();
  const [time, setTime] = useState<string>("");
  const [togglingHotl, setTogglingHotl] = useState<boolean>(false);
  const [coreHealthy, setCoreHealthy] = useState<boolean | null>(null);

  const canToggleHotl = isAdmin(user);
  const hotlEnabled = status?.hotl_enabled;
  const simulation = status?.simulation_mode === true;

  useEffect(() => {
    const updateTime = () => setTime(new Date().toUTCString().slice(17, 25) + " UTC");
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const checkHealth = useCallback(async () => {
    setCoreHealthy(await api.getHealth());
  }, []);

  useEffect(() => {
    void checkHealth();
  }, [checkHealth]);
  usePolling(() => void checkHealth(), 30_000);

  const handleToggleHotl = async () => {
    if (togglingHotl || hotlEnabled === undefined || !canToggleHotl) return;
    const enabling = !hotlEnabled;

    const ok = await confirm(
      enabling
        ? {
            title: "Enable autonomous containment (HOTL)?",
            message: simulation
              ? "HOTL playbooks will run response actions without waiting for an analyst whenever there is real evidence (a Malicious indicator backed by live or lab intelligence, or Critical telemetry) and policy allows it. Simulation mode is ON, so those actions are only rehearsed."
              : "HOTL playbooks will run response actions against your REAL systems without waiting for an analyst whenever there is real evidence (a Malicious indicator backed by live intelligence, or Critical telemetry) and policy allows it. Simulation mode is OFF.",
            items: [
              "Protected hosts, users and IPs are still refused by policy.",
              "The switch can be paused again from this bar at any time.",
              "The change is recorded in the audit log.",
            ],
            confirmLabel: "Enable HOTL",
            tone: simulation ? "warning" : "danger",
          }
        : {
            title: "Pause autonomous containment (HOTL)?",
            message: "Every containment action will wait for an analyst to approve it until HOTL is enabled again. Alerts already waiting are not affected.",
            confirmLabel: "Pause HOTL",
            tone: "warning",
          }
    );
    if (!ok) return;

    setTogglingHotl(true);
    try {
      const res = await api.toggleHotl(enabling);
      await refresh();
      toast.success(
        res.hotl_enabled
          ? "HOTL enabled: HOTL playbooks may contain automatically when there is real evidence and policy allows it."
          : "HOTL paused: every containment action waits for analyst approval."
      );
    } catch (err) {
      const blockers = errorBlockers(err);
      if (blockers.length > 0) {
        await confirm({
          title: "HOTL cannot be enabled yet",
          message: `${describeError(err)} Resolve these first (Configuration > Orchestration), then try again:`,
          items: blockers,
          hideCancel: true,
          confirmLabel: "Understood",
          tone: "warning",
        });
      } else {
        toast.error(`Could not change HOTL state: ${describeError(err)}`);
      }
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
          role="status"
          className="flex items-center space-x-2"
          title={coreHealthy === null ? "Checking API..." : coreHealthy ? "SOAR API reachable (/api/health)" : "SOAR API unreachable"}
        >
          <div
            aria-hidden="true"
            className={`h-2.5 w-2.5 rounded-full ${coreHealthy === null ? "bg-slate-500" : coreHealthy ? "bg-emerald-500" : "bg-rose-500"}`}
          />
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            {coreHealthy === null ? "API // CHECKING" : coreHealthy ? "API // ONLINE" : "API // UNREACHABLE"}
          </span>
        </div>

        {simulation && (
          <div
            className="flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-fuchsia-500/15 border border-fuchsia-500/40 text-fuchsia-300 text-xs font-black tracking-wider"
            title="Simulation mode is ON: response actions against unconfigured connectors are only rehearsed (recorded as SIMULATED, nothing is changed on real systems, alerts are NOT contained), and lab threat-intel fixtures are used for documentation IPs and demo IOCs."
          >
            <FlaskConical className="h-3.5 w-3.5" aria-hidden="true" />
            <span>SIMULATION MODE</span>
          </div>
        )}

        {statusError && (
          <div
            role="alert"
            className="hidden lg:flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-amber-500/30 text-amber-300 text-xs"
            title={statusError}
          >
            <AlertCircle className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{status ? "Runtime status stale" : "Runtime status unavailable"}</span>
          </div>
        )}
      </div>

      {/* Right: clock, integrations, HOTL */}
      <div className="flex items-center space-x-3">
        <div className="font-mono text-xs text-slate-300 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-lg shadow-inner">
          {time || "--:--:-- UTC"}
        </div>

        {status &&
          (isSecEngOrAdmin(user) ? (
            <Link
              href="/configuration"
              className="hidden sm:flex items-center space-x-1.5 bg-slate-900 border border-slate-800 text-slate-300 px-2.5 py-1.5 rounded-lg text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
              title={integrationTitle}
            >
              <Plug className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
              <span>
                {configuredCount}/{integrationEntries.length} integrations configured
              </span>
            </Link>
          ) : (
            <div
              className="hidden sm:flex items-center space-x-1.5 bg-slate-900 border border-slate-800 text-slate-300 px-2.5 py-1.5 rounded-lg text-xs font-medium"
              title={integrationTitle}
            >
              <Plug className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
              <span>
                {configuredCount}/{integrationEntries.length} integrations configured
              </span>
            </div>
          ))}

        {hotlEnabled === undefined ? (
          <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 text-slate-400 px-3 py-1.5 rounded-lg text-xs font-semibold">
            <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
            <span>HOTL: unknown</span>
          </div>
        ) : (
          <button
            type="button"
            onClick={handleToggleHotl}
            disabled={togglingHotl || !canToggleHotl}
            aria-pressed={hotlEnabled}
            title={
              (hotlEnabled
                ? "HOTL enabled: HOTL playbooks may contain automatically when there is real evidence (Malicious IOC or Critical telemetry) and policy allows it."
                : "HOTL paused: all containment waits for analyst approval (HITL).") +
              (canToggleHotl ? " Click to change (asks for confirmation)." : " Only administrators can change this.")
            }
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold shadow-sm transition-all duration-150 border disabled:cursor-default focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${
              hotlEnabled ? "bg-blue-600/15 border-blue-500/30 text-blue-300" : "bg-amber-500/15 border-amber-500/40 text-amber-300"
            } ${canToggleHotl ? "hover:brightness-125 active:scale-95" : ""} ${togglingHotl ? "opacity-50" : ""}`}
          >
            {hotlEnabled ? <ShieldCheck className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" /> : <ShieldAlert className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />}
            <span>{hotlEnabled ? "HOTL: Enabled" : "HOTL: Paused (HITL only)"}</span>
            {canToggleHotl && <Power className="h-3.5 w-3.5 opacity-70" aria-hidden="true" />}
          </button>
        )}
      </div>
    </header>
  );
}
