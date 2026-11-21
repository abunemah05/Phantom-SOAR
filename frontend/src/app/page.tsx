"use client";

import React, { useCallback, useState } from "react";
import Link from "next/link";
import {
  Activity, AlertTriangle, Bot, ChevronRight, Clock, Cpu, FlaskConical, Layers, ShieldAlert, Trash2, Zap,
} from "lucide-react";
import { Alert, DashboardMetrics } from "@/lib/types";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { formatDuration } from "@/lib/format";
import { canAdminister } from "@/lib/roles";
import { useResource } from "@/hooks/useResource";
import InvestigateModal from "@/components/InvestigateModal";
import { useAuth } from "@/components/AuthGate";
import { useConfirm } from "@/components/ConfirmDialog";
import { useRuntimeStatus } from "@/components/RuntimeStatusProvider";
import { EmptyState, ErrorState, InlineNotice, LoadingState, StaleBanner } from "@/components/StateViews";
import { AlertStatusBadge, SeverityBadge } from "@/components/StatusBadges";
import { useToast } from "@/components/Toast";

interface DashboardData {
  metrics: DashboardMetrics;
  recent: Alert[];
}

const SEVERITY_ROWS: Array<{ key: keyof DashboardMetrics; label: string; text: string; bar: string }> = [
  { key: "critical_count", label: "Critical", text: "text-rose-400", bar: "bg-rose-500" },
  { key: "high_count", label: "High", text: "text-orange-400", bar: "bg-orange-500" },
  { key: "medium_count", label: "Medium", text: "text-amber-400", bar: "bg-amber-500" },
  { key: "low_count", label: "Low", text: "text-blue-400", bar: "bg-blue-500" },
];

export default function DashboardPage() {
  const { user } = useAuth();
  const { status: runtime } = useRuntimeStatus();
  const toast = useToast();
  const confirm = useConfirm();
  const admin = canAdminister(user);
  const simulationMode = runtime?.simulation_mode === true;

  const fetcher = useCallback(async (): Promise<DashboardData> => {
    const [metrics, recent] = await Promise.all([api.getDashboardMetrics(), api.getAlerts({ limit: 6 })]);
    return { metrics, recent: recent || [] };
  }, []);
  // Paused automatically while the tab is hidden.
  const dashboard = useResource(fetcher, { pollMs: 15_000 });

  // The AI tile is optional: an older backend without the agent router simply hides it.
  const agentFetcher = useCallback(() => api.getAgentStatus(), []);
  const agent = useResource(agentFetcher, { pollMs: 30_000 });

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [seeding, setSeeding] = useState(false);
  const [purging, setPurging] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const metrics = dashboard.data?.metrics;
  const recent = dashboard.data?.recent ?? [];

  const seedDemo = async () => {
    const ok = await confirm({
      title: "Generate demo alerts?",
      message: "Lab alert payloads are sent through the real ingestion pipeline.",
      items: ["New alerts appear in the queue.", "Threat-intel uses lab fixtures and response actions are only simulated (simulation mode)."],
      confirmLabel: "Generate demo data",
    });
    if (!ok) return;
    setSeeding(true);
    setActionError(null);
    try {
      const res = await api.seedDemoData();
      toast.success(res?.message || "Lab alerts were sent through the ingestion pipeline. Their response actions are simulated.");
      await dashboard.reload();
    } catch (err) {
      setActionError(`Demo data was not generated: ${describeError(err)}`);
    } finally {
      setSeeding(false);
    }
  };

  const purge = async () => {
    const count = metrics?.total_alerts;
    const ok = await confirm({
      title: "Purge ALL alert cases?",
      message: `This permanently deletes ${typeof count === "number" ? `all ${count}` : "every"} alert case from the database, with its IoC artifacts, playbook executions and containment records. It cannot be undone.`,
      items: [
        "Incident reports and AI proposals attached to those alerts are removed with them.",
        "The security audit log is kept and records who purged the queue.",
      ],
      confirmLabel: "Purge all cases",
      tone: "danger",
      requireText: "PURGE",
    });
    if (!ok) return;
    setPurging(true);
    setActionError(null);
    try {
      // Two steps inside the client: a one-time confirmation token is requested, then the purge presents it.
      const res = await api.purgeAlerts();
      toast.success(res?.message || "All alert cases were purged.");
      await dashboard.reload();
    } catch (err) {
      setActionError(`Purge failed: ${describeError(err)}`);
    } finally {
      setPurging(false);
    }
  };

  const reviewCount = metrics ? metrics.review_gates_count ?? metrics.unresolved_alerts ?? metrics.triaged_alerts + metrics.new_alerts : null;
  const severityTotal = metrics ? metrics.critical_count + metrics.high_count + metrics.medium_count + metrics.low_count : 0;
  const simulated = metrics?.simulated_alerts ?? 0;

  return (
    <div className="space-y-8 animate-fade-in">
      <div className="bg-gradient-to-r from-slate-900 via-blue-950/30 to-slate-900 border border-slate-800 rounded-2xl p-6 lg:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-xl shadow-black/40">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2.5 flex-wrap">
            <h1 className="text-2xl font-black text-white tracking-tight">Phantom SOAR Mission Control</h1>
            {runtime &&
              (simulationMode ? (
                <span className="text-xs px-2 py-0.5 rounded-full bg-fuchsia-500/20 text-fuchsia-300 font-bold border border-fuchsia-500/30 flex items-center gap-1">
                  <FlaskConical className="h-3 w-3" aria-hidden="true" /> SIMULATION
                </span>
              ) : (
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">LIVE CONNECTORS ONLY</span>
              ))}
          </div>
          <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
            SIEM / EDR alert intake, multi-provider threat-intel enrichment, policy-guarded playbooks, analyst review gates (HITL), optional autonomous containment (HOTL) and AI-assisted triage.
          </p>
          {simulationMode && (
            <p className="text-[11px] text-fuchsia-300/90 max-w-2xl">
              Simulation mode is on: actions are only rehearsed and recorded as SIMULATED. Nothing is contained on real systems.
            </p>
          )}
        </div>

        {admin && (
          <div className="flex flex-col sm:flex-row items-center gap-3">
            {simulationMode && (
              <button
                type="button"
                onClick={() => void seedDemo()}
                disabled={seeding || purging}
                title="Sends lab alert payloads through the real ingestion pipeline (simulation mode only)"
                className="w-full sm:w-auto flex items-center justify-center gap-2.5 px-6 py-3.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm shadow-xl shadow-blue-600/30 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-300"
              >
                <Zap className={`h-4 w-4 ${seeding ? "animate-spin text-amber-600" : "text-amber-600"}`} aria-hidden="true" />
                <span>{seeding ? "Ingesting lab alerts..." : "Generate demo data"}</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => void purge()}
              disabled={seeding || purging}
              title="Delete all alert cases (administrators only)"
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-3.5 rounded-xl bg-slate-800/80 hover:bg-rose-950/40 text-slate-300 hover:text-rose-400 border border-slate-700 hover:border-rose-500/40 font-semibold text-xs disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
            >
              <Trash2 className={`h-3.5 w-3.5 ${purging ? "animate-spin text-rose-400" : ""}`} aria-hidden="true" />
              <span>{purging ? "Purging cases..." : "Purge all cases"}</span>
            </button>
          </div>
        )}
      </div>

      {actionError && <InlineNotice tone="error" onDismiss={() => setActionError(null)}>{actionError}</InlineNotice>}

      {dashboard.error && !dashboard.data ? (
        <ErrorState title="The dashboard could not be loaded" message={dashboard.error} onRetry={() => void dashboard.reload()} />
      ) : dashboard.loading && !dashboard.data ? (
        <LoadingState label="Loading SOC metrics..." />
      ) : (
        <>
          {dashboard.error && <StaleBanner message={dashboard.error} onRetry={() => void dashboard.reload()} />}

          <section aria-label="SOC metrics" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Link href="/alerts?status=new" className="bg-slate-900/90 border border-slate-800/80 hover:border-blue-500/50 rounded-xl p-5 shadow-lg group transition block focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
              <div className="flex items-center justify-between text-slate-400 mb-2">
                <span className="text-xs font-bold uppercase tracking-wider group-hover:text-blue-300">New alerts</span>
                <div className="h-8 w-8 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400"><ShieldAlert className="h-4 w-4" aria-hidden="true" /></div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-white">{metrics?.new_alerts ?? "--"}</span>
                <span className="text-xs text-slate-500 font-medium">pending intake</span>
              </div>
              <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between pt-2 border-t border-slate-800/60">
                <span>Total logged cases</span>
                <span className="font-bold text-slate-200">{metrics?.total_alerts ?? 0}</span>
              </div>
            </Link>

            <Link href={metrics?.review_gates_count !== undefined ? "/alerts?status=review" : "/alerts?status=unresolved"} className="bg-slate-900/90 border border-amber-500/30 hover:border-amber-400 rounded-xl p-5 shadow-lg shadow-amber-950/20 group transition block ring-1 ring-amber-500/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold uppercase tracking-wider text-amber-300">Review gates (HITL)</span>
                <div className="h-8 w-8 rounded-lg bg-amber-500/20 flex items-center justify-center text-amber-400"><AlertTriangle className="h-4 w-4" aria-hidden="true" /></div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-amber-400">{reviewCount ?? "--"}</span>
                <span className="text-xs text-slate-400 font-medium">{metrics?.review_gates_count !== undefined ? "awaiting a decision" : "unresolved cases"}</span>
              </div>
              <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between pt-2 border-t border-slate-800/60">
                <span>Human in the loop</span>
                <span className="font-bold text-amber-400">Open review gate &rarr;</span>
              </div>
            </Link>

            <div className="bg-slate-900/90 border border-slate-800/80 rounded-xl p-5 shadow-lg">
              <div className="flex items-center justify-between text-slate-400 mb-2">
                <span className="text-xs font-bold uppercase tracking-wider">Response actions</span>
                <div className="h-8 w-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400"><Cpu className="h-4 w-4" aria-hidden="true" /></div>
              </div>
              <dl className="space-y-1.5">
                <div className="flex items-baseline justify-between">
                  <dt className="text-[11px] text-slate-400">
                    <Link href="/alerts?status=contained" className="underline decoration-dotted hover:text-emerald-300">Contained</Link> (live)
                  </dt>
                  <dd className="text-2xl font-black text-emerald-400">{metrics?.contained_alerts ?? "--"}</dd>
                </div>
                <div className="flex items-baseline justify-between">
                  <dt className="text-[11px] text-fuchsia-300">
                    <Link href="/alerts?status=simulated" className="underline decoration-dotted hover:text-fuchsia-200">Simulated</Link> (not contained)
                  </dt>
                  <dd className="text-2xl font-black text-fuchsia-300">{metrics ? simulated : "--"}</dd>
                </div>
              </dl>
              <div className="mt-2 text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
                {metrics?.live_actions !== undefined || metrics?.simulated_actions !== undefined ? (
                  <span>
                    Actions: {metrics?.live_actions ?? 0} live, {metrics?.simulated_actions ?? 0} simulated
                    {metrics?.blocked_actions ? `, ${metrics.blocked_actions} blocked` : ""}
                    {metrics?.failed_actions ? `, ${metrics.failed_actions} failed` : ""}
                  </span>
                ) : (
                  <span>{metrics?.automated_actions ?? 0} automated actions (live and simulated)</span>
                )}
              </div>
            </div>

            <Link href="/reports" className="bg-slate-900/90 border border-slate-800/80 hover:border-indigo-500/50 rounded-xl p-5 shadow-lg group transition block focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400">
              <div className="flex items-center justify-between text-slate-400 mb-2">
                <span className="text-xs font-bold uppercase tracking-wider group-hover:text-indigo-300">Average MTTR</span>
                <div className="h-8 w-8 rounded-lg bg-indigo-500/10 flex items-center justify-center text-indigo-400"><Clock className="h-4 w-4" aria-hidden="true" /></div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-indigo-400">{metrics ? formatDuration(metrics.avg_mttr_seconds) : "--"}</span>
                <span className="text-xs text-slate-500 font-medium">alert to response</span>
              </div>
              <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between pt-2 border-t border-slate-800/60">
                <span>{metrics?.mttr_sample_size !== undefined ? `Over ${metrics.mttr_sample_size} runs` : "Resolved cases"}</span>
                <span className="font-bold text-slate-300">{metrics?.mttr_sample_size !== undefined ? "" : metrics?.resolved_alerts ?? 0}</span>
              </div>
            </Link>
          </section>

          {simulated > 0 && (
            <InlineNotice tone="warning">
              <b>{simulated} alert{simulated === 1 ? " is" : "s are"} SIMULATED, not contained.</b> Their response actions were only rehearsed; the threat has not been stopped on any real system.
            </InlineNotice>
          )}

          {agent.data && (
            <Link href="/agent" className="bg-slate-900/90 border border-cyan-500/20 hover:border-cyan-400/50 rounded-xl p-4 flex items-center justify-between gap-4 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400">
              <div className="flex items-center gap-3 text-sm">
                <Bot className="h-5 w-5 text-cyan-300" aria-hidden="true" />
                <span className="font-semibold text-slate-200">AI agent</span>
                <span className="text-xs text-slate-400">
                  {agent.data.enabled ? (agent.data.configured ? "enabled" : "enabled, no API key") : "disabled"}
                  {agent.data.autonomy === "recommend_only" ? " · recommend only" : ""}
                </span>
              </div>
              <span className={`text-xs font-bold ${agent.data.pending_proposals > 0 ? "text-amber-300" : "text-slate-500"}`}>
                {agent.data.pending_proposals} proposal{agent.data.pending_proposals === 1 ? "" : "s"} awaiting a decision
              </span>
            </Link>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <section aria-labelledby="picerl-heading" className="lg:col-span-2 bg-slate-900/90 border border-slate-800/80 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h2 id="picerl-heading" className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Layers className="h-4 w-4 text-blue-400" aria-hidden="true" /> SANS PICERL incident response lifecycle
                </h2>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2 pt-2">
                {[
                  { phase: "Preparation", desc: "Playbooks and policy", color: "border-blue-500/40 bg-blue-500/5" },
                  { phase: "Identification", desc: "SIEM ingest + TIP", color: "border-indigo-500/40 bg-indigo-500/5" },
                  { phase: "Containment", desc: "HOTL / HITL gate", color: "border-emerald-500/40 bg-emerald-500/5" },
                  { phase: "Eradication", desc: "Kill process / block IP", color: "border-purple-500/40 bg-purple-500/5" },
                  { phase: "Recovery", desc: "Session revocation", color: "border-amber-500/40 bg-amber-500/5" },
                  { phase: "Lessons", desc: "PDF incident report", color: "border-rose-500/40 bg-rose-500/5" },
                ].map((p, idx) => (
                  <div key={p.phase} className={`p-3 rounded-lg border flex flex-col justify-between ${p.color}`}>
                    <span className="text-[10px] font-mono font-bold uppercase text-slate-400">Phase 0{idx + 1}</span>
                    <span className="text-xs font-bold mt-1 text-white">{p.phase}</span>
                    <span className="text-[10px] text-slate-400 mt-1">{p.desc}</span>
                  </div>
                ))}
              </div>
            </section>

            <section aria-labelledby="sev-heading" className="bg-slate-900/90 border border-slate-800/80 rounded-xl p-6 space-y-4">
              <h2 id="sev-heading" className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-rose-400" aria-hidden="true" /> Severity matrix
              </h2>
              <div className="space-y-3 pt-1">
                {SEVERITY_ROWS.map((row) => {
                  const count = Number(metrics?.[row.key] ?? 0);
                  const pct = severityTotal > 0 ? Math.round((count / severityTotal) * 100) : 0;
                  return (
                    <div key={row.key}>
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span className={`${row.text} font-bold`}>{row.label}</span>
                        <span className="font-mono text-white font-bold">{count}</span>
                      </div>
                      <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden" role="presentation">
                        <div className={`h-full ${row.bar} rounded-full transition-all duration-300`} style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>
          </div>

          <section aria-labelledby="recent-heading" className="bg-slate-900/90 border border-slate-800/80 rounded-xl overflow-hidden shadow-xl">
            <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Activity className="h-4 w-4 text-blue-400" aria-hidden="true" />
                <h2 id="recent-heading" className="text-sm font-bold text-white uppercase tracking-wider">Recent security telemetry</h2>
              </div>
              <Link href="/alerts" className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1">
                <span>View all cases</span> <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <caption className="sr-only">Most recent alerts</caption>
                <thead className="bg-slate-950/60 text-slate-400 font-bold uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th scope="col" className="py-3 px-4">Alert</th>
                    <th scope="col" className="py-3 px-4">Rule / description</th>
                    <th scope="col" className="py-3 px-4">Severity</th>
                    <th scope="col" className="py-3 px-4">Status</th>
                    <th scope="col" className="py-3 px-4">IoCs and max TIP score</th>
                    <th scope="col" className="py-3 px-4">Source</th>
                    <th scope="col" className="py-3 px-4 text-right"><span className="sr-only">Open</span></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {recent.length === 0 ? (
                    <tr>
                      <td colSpan={7}>
                        <EmptyState icon={ShieldAlert} title="No alerts in the queue">
                          Alerts arrive through the authenticated webhooks (/api/webhooks/wazuh, /edr, /xdr).
                        </EmptyState>
                      </td>
                    </tr>
                  ) : (
                    recent.map((alert) => (
                      <tr key={alert.alert_id} className="hover:bg-slate-800/40 transition">
                        <td className="py-3.5 px-4 font-mono font-bold text-white">#{alert.alert_id}</td>
                        <td className="py-3.5 px-4 max-w-xs truncate text-slate-200">
                          <span className="font-semibold block">{alert.rule_id}</span>
                          <span className="text-[11px] text-slate-400 truncate block">{alert.raw_payload?.rule?.description || alert.rule_id}</span>
                        </td>
                        <td className="py-3.5 px-4"><SeverityBadge severity={alert.severity} /></td>
                        <td className="py-3.5 px-4"><AlertStatusBadge status={alert.status} /></td>
                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-slate-300">{alert.ioc_count || 0} artifacts</span>
                            {(alert.max_threat_score || 0) > 0 && (
                              <span className="text-[10px] px-1.5 rounded bg-rose-500/10 text-rose-400 font-mono font-bold">TIP {alert.max_threat_score}/100</span>
                            )}
                          </div>
                        </td>
                        <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">{alert.source}</td>
                        <td className="py-3.5 px-4 text-right">
                          <button
                            type="button"
                            onClick={() => setSelectedId(alert.alert_id)}
                            aria-label={`Investigate alert ${alert.alert_id}`}
                            className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600 text-blue-300 hover:text-white border border-blue-500/30 rounded-lg text-xs font-semibold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
                          >
                            Investigate
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      <InvestigateModal
        alertId={selectedId}
        isOpen={selectedId !== null}
        onClose={() => setSelectedId(null)}
        onAlertUpdated={() => void dashboard.reload()}
      />
    </div>
  );
}
