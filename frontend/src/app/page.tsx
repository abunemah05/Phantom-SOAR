"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { 
  ShieldAlert, 
  Activity, 
  Clock, 
  Zap, 
  Database, 
  RefreshCw, 
  ArrowRight, 
  CheckCircle, 
  Layers, 
  AlertTriangle,
  Play,
  Cpu,
  ChevronRight,
  Trash2,
  FlaskConical,
  AlertCircle
} from "lucide-react";
import { DashboardMetrics, Alert } from "@/lib/types";
import { api } from "@/lib/api";
import { isAdmin } from "@/lib/roles";
import { formatDuration } from "@/lib/format";
import InvestigateModal from "@/components/InvestigateModal";
import { useAuth } from "@/components/AuthGate";
import { useRuntimeStatus } from "@/components/RuntimeStatusProvider";

export default function DashboardPage() {
  const { user } = useAuth();
  const { status: runtime } = useRuntimeStatus();
  const admin = isAdmin(user);
  const simulationMode = runtime?.simulation_mode === true;
  const canSeedDemo = admin && simulationMode;

  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [seeding, setSeeding] = useState<boolean>(false);
  const [purging, setPurging] = useState<boolean>(false);
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [seedSuccessMsg, setSeedSuccessMsg] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      const [m, a] = await Promise.all([
        api.getDashboardMetrics(),
        api.getAlerts({ limit: 6 })
      ]);
      setMetrics(m);
      setRecentAlerts(a || []);
    } catch (e: any) {
      console.error("Failed to load dashboard data:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 6000);
    return () => clearInterval(interval);
  }, []);

  const handleSeedDemo = async () => {
    setSeeding(true);
    setSeedSuccessMsg(null);
    setActionError(null);
    try {
      const res = await api.seedDemoData();
      setSeedSuccessMsg(
        res?.message ||
          "Lab alerts were sent through the ingestion pipeline. Their enrichment uses lab fixtures and any response actions are simulated."
      );
      await loadData();
      setTimeout(() => setSeedSuccessMsg(null), 8000);
    } catch (err: any) {
      setActionError(`Demo data was not generated: ${err.message || "request failed"}`);
    } finally {
      setSeeding(false);
    }
  };

  const handlePurgeData = async () => {
    if (!confirm("Are you sure you want to purge all alert cases and reset the queue?")) return;
    setPurging(true);
    setSeedSuccessMsg(null);
    setActionError(null);
    try {
      const res = await api.purgeAlerts();
      setSeedSuccessMsg(res?.message || "All alert cases were purged.");
      await loadData();
      setTimeout(() => setSeedSuccessMsg(null), 5000);
    } catch (err: any) {
      setActionError(`Purge failed: ${err.message || "request failed"}`);
    } finally {
      setPurging(false);
    }
  };

  const openInvestigate = (id: number) => {
    setSelectedAlertId(id);
    setIsModalOpen(true);
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "high":
        return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "medium":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      default:
        return "bg-blue-500/10 text-blue-400 border-blue-500/30";
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case "contained":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "triaged":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "closed":
      case "resolved":
        return "bg-slate-500/10 text-slate-400 border-slate-500/30";
      default:
        return "bg-blue-500/10 text-blue-400 border-blue-500/30";
    }
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header Banner & Demo Seeder Action */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 rounded-2xl p-6 lg:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-xl shadow-black/40">
        <div className="space-y-1.5">
          <div className="flex items-center space-x-2.5">
            <h1 className="text-2xl font-black text-white tracking-tight">
              Phantom SOAR Mission Control
            </h1>
            {runtime && (
              simulationMode ? (
                <span className="text-xs px-2 py-0.5 rounded-full bg-fuchsia-500/20 text-fuchsia-300 font-bold border border-fuchsia-500/30 flex items-center gap-1">
                  <FlaskConical className="h-3 w-3" />
                  SIMULATION
                </span>
              ) : (
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">
                  LIVE CONNECTORS ONLY
                </span>
              )
            )}
          </div>
          <p className="text-sm text-slate-400 max-w-2xl leading-relaxed">
            SIEM / EDR alert intake, multi-provider threat-intel enrichment, policy-guarded playbooks,
            analyst review gates (HITL) and optional autonomous containment (HOTL) with PDF incident reports.
          </p>
          {simulationMode && (
            <p className="text-[11px] text-fuchsia-300/90 max-w-2xl">
              Simulation mode is on: actions against connectors that are not configured are recorded as SIMULATED and change nothing on real systems.
            </p>
          )}
        </div>

        {/* PROMINENT DEMO SEEDER & DATA CONTROLS */}
        {admin && (
          <div className="flex flex-col sm:flex-row items-center gap-3">
            {canSeedDemo && (
              <button
                onClick={handleSeedDemo}
                disabled={seeding || purging}
                title="Sends lab alert payloads through the real ingestion pipeline (simulation mode only)"
                className="w-full sm:w-auto flex items-center justify-center space-x-2.5 px-6 py-3.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold text-sm shadow-xl shadow-blue-600/30 transition transform hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-50"
              >
                <Zap className={`h-4 w-4 ${seeding ? "animate-spin text-amber-300" : "text-amber-400"}`} />
                <span>{seeding ? "Ingesting Lab Alerts..." : "Generate Demo Data"}</span>
              </button>
            )}

            <button
              onClick={handlePurgeData}
              disabled={seeding || purging}
              className="w-full sm:w-auto flex items-center justify-center space-x-2 px-4 py-3.5 rounded-xl bg-slate-800/80 hover:bg-rose-950/40 text-slate-300 hover:text-rose-400 border border-slate-700 hover:border-rose-500/40 font-semibold text-xs transition disabled:opacity-50"
              title="Delete all alert cases (admin only)"
            >
              <Trash2 className={`h-3.5 w-3.5 ${purging ? "animate-spin text-rose-400" : ""}`} />
              <span>{purging ? "Purging Cases..." : "Purge All Cases"}</span>
            </button>
          </div>
        )}
      </div>

      {actionError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-semibold flex items-center justify-between animate-fade-in">
          <span className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            {actionError}
          </span>
          <button onClick={() => setActionError(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {seedSuccessMsg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold flex items-center justify-between animate-fade-in">
          <span className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4" />
            {seedSuccessMsg}
          </span>
          <button onClick={() => setSeedSuccessMsg(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Real-time SOC Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: New Alerts */}
        <Link
          href="/alerts?status=new"
          className="bg-slate-900/90 border border-slate-800/80 hover:border-blue-500/50 rounded-xl p-5 shadow-lg relative overflow-hidden group transition block cursor-pointer"
          title="Filter alerts queue for newly ingested events"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-bold uppercase tracking-wider group-hover:text-blue-300 transition">New Ingested Alerts</span>
            <div className="h-8 w-8 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400 group-hover:scale-110 transition">
              <ShieldAlert className="h-4 w-4" />
            </div>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black text-white">
              {metrics ? metrics.new_alerts : "--"}
            </span>
            <span className="text-xs text-slate-500 font-medium">pending intake</span>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between pt-2 border-t border-slate-800/60 group-hover:text-blue-300 transition">
            <span>Total Logged Cases:</span>
            <span className="font-bold text-slate-200">{metrics?.total_alerts || 0}</span>
          </div>
        </Link>

        {/* Metric 2: Review Gates (HITL) - Dynamic count of unresolved cases */}
        <Link
          href="/alerts?status=unresolved"
          className="bg-slate-900/90 border border-amber-500/30 hover:border-amber-400 rounded-xl p-5 shadow-lg shadow-amber-950/20 relative overflow-hidden group transition cursor-pointer hover:bg-slate-900/95 block ring-1 ring-amber-500/20 hover:ring-amber-400/50"
          title="Click to view all unresolved cases awaiting analyst review"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-amber-300 flex items-center gap-1.5">
              Review Gates (HITL)
              <span className="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            </span>
            <div className="h-8 w-8 rounded-lg bg-amber-500/20 flex items-center justify-center text-amber-400 group-hover:scale-110 transition">
              <AlertTriangle className="h-4 w-4" />
            </div>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black text-amber-400">
              {metrics ? (metrics.unresolved_alerts ?? (metrics.triaged_alerts + (metrics.new_alerts || 0))) : "--"}
            </span>
            <span className="text-xs text-slate-400 font-medium">unresolved cases</span>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between pt-2 border-t border-slate-800/60 group-hover:text-amber-300 transition">
            <span>Human-In-The-Loop:</span>
            <span className="font-bold text-amber-400 flex items-center gap-1 group-hover:translate-x-1 transition">
              Enter Review Gate &rarr;
            </span>
          </div>
        </Link>

        {/* Metric 3: Automated Containment Actions */}
        <Link
          href="/alerts?status=contained"
          className="bg-slate-900/90 border border-slate-800/80 hover:border-emerald-500/50 rounded-xl p-5 shadow-lg relative overflow-hidden group transition block cursor-pointer"
          title="Filter alerts queue for contained cases"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-bold uppercase tracking-wider group-hover:text-emerald-300 transition">Automated Actions</span>
            <div className="h-8 w-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400 group-hover:scale-110 transition">
              <Cpu className="h-4 w-4" />
            </div>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black text-emerald-400">
              {metrics ? metrics.automated_actions : "--"}
            </span>
            <span className="text-xs text-slate-500 font-medium">EDR / firewall / IAM / ITSM</span>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between pt-2 border-t border-slate-800/60 group-hover:text-emerald-300 transition">
            <span>Contained Cases:</span>
            <span className="font-bold text-emerald-400">{metrics?.contained_alerts || 0}</span>
          </div>
        </Link>

        {/* Metric 4: Avg MTTR */}
        <Link
          href="/reports"
          className="bg-slate-900/90 border border-slate-800/80 hover:border-indigo-500/50 rounded-xl p-5 shadow-lg relative overflow-hidden group transition block cursor-pointer"
          title="View SOC performance & analyst reporting engine"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-bold uppercase tracking-wider group-hover:text-indigo-300 transition">Average MTTR</span>
            <div className="h-8 w-8 rounded-lg bg-indigo-500/10 flex items-center justify-center text-indigo-400 group-hover:scale-110 transition">
              <Clock className="h-4 w-4" />
            </div>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-3xl font-black text-indigo-400">
              {metrics ? formatDuration(metrics.avg_mttr_seconds) : "--"}
            </span>
            <span className="text-xs text-slate-500 font-medium">alert to response</span>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between pt-2 border-t border-slate-800/60 group-hover:text-indigo-300 transition">
            <span>Resolved Cases:</span>
            <span className="font-bold text-slate-300">{metrics?.resolved_alerts ?? 0}</span>
          </div>
        </Link>
      </div>

      {/* SANS PICERL Architecture & Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* SANS PICERL Flow */}
        <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800/80 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Layers className="h-4 w-4 text-blue-400" />
              SANS PICERL Incident Response Lifecycle
            </h2>
            <span className="text-xs text-slate-400 font-mono">SOAPA Orchestrated</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2 pt-2">
            {[
              { phase: "Preparation", desc: "Playbooks & policy", color: "border-blue-500/40 bg-blue-500/5 text-blue-300" },
              { phase: "Identification", desc: "SIEM ingest + TIP", color: "border-indigo-500/40 bg-indigo-500/5 text-indigo-300" },
              { phase: "Containment", desc: "HOTL / HITL Gate", color: "border-emerald-500/40 bg-emerald-500/5 text-emerald-300" },
              { phase: "Eradication", desc: "Proc Kill / IP Block", color: "border-purple-500/40 bg-purple-500/5 text-purple-300" },
              { phase: "Recovery", desc: "Session Revocation", color: "border-amber-500/40 bg-amber-500/5 text-amber-300" },
              { phase: "Lessons", desc: "PDF Incident Report", color: "border-rose-500/40 bg-rose-500/5 text-rose-300" },
            ].map((p, idx) => (
              <div key={idx} className={`p-3 rounded-lg border flex flex-col justify-between ${p.color}`}>
                <span className="text-[10px] font-mono font-bold uppercase opacity-75">Phase 0{idx + 1}</span>
                <span className="text-xs font-bold mt-1 text-white">{p.phase}</span>
                <span className="text-[10px] opacity-80 mt-1">{p.desc}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Distribution */}
        <div className="bg-slate-900/90 border border-slate-800/80 rounded-xl p-6 space-y-4">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-rose-400" />
            Severity Matrix
          </h2>

          <div className="space-y-3 pt-1">
            {(() => {
              const total = (metrics?.critical_count || 0) + (metrics?.high_count || 0) + (metrics?.medium_count || 0) + (metrics?.low_count || 0);
              const getWidth = (cnt: number) => (total > 0 ? `${Math.round((cnt / total) * 100)}%` : "0%");

              return (
                <>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-rose-400 font-bold">Critical</span>
                    <span className="font-mono text-white font-bold">{metrics?.critical_count || 0}</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div className="h-full bg-rose-500 rounded-full transition-all duration-300" style={{ width: getWidth(metrics?.critical_count || 0) }} />
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <span className="text-orange-400 font-bold">High</span>
                    <span className="font-mono text-white font-bold">{metrics?.high_count || 0}</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div className="h-full bg-orange-500 rounded-full transition-all duration-300" style={{ width: getWidth(metrics?.high_count || 0) }} />
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <span className="text-amber-400 font-bold">Medium</span>
                    <span className="font-mono text-white font-bold">{metrics?.medium_count || 0}</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div className="h-full bg-amber-500 rounded-full transition-all duration-300" style={{ width: getWidth(metrics?.medium_count || 0) }} />
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <span className="text-blue-400 font-bold">Low</span>
                    <span className="font-mono text-white font-bold">{metrics?.low_count || 0}</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div className="h-full bg-blue-500 rounded-full transition-all duration-300" style={{ width: getWidth(metrics?.low_count || 0) }} />
                  </div>
                </>
              );
            })()}
          </div>
        </div>
      </div>

      {/* Recent Alerts Feed Table */}
      <div className="bg-slate-900/90 border border-slate-800/80 rounded-xl overflow-hidden shadow-xl">
        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <Activity className="h-4 w-4 text-blue-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Recent Ingested Security Telemetry
            </h2>
          </div>
          <Link
            href="/alerts"
            className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center space-x-1"
          >
            <span>View All Cases</span>
            <ChevronRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 font-bold uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Alert ID</th>
                <th className="py-3 px-4">Rule / Description</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">IoCs & Max TIP Score</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {recentAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-14 text-center">
                    <div className="flex flex-col items-center justify-center space-y-2.5">
                      <div className="h-10 w-10 rounded-xl bg-slate-800/80 border border-slate-700/80 flex items-center justify-center text-slate-400">
                        <ShieldAlert className="h-5 w-5 text-slate-400" />
                      </div>
                      <span className="text-xs font-semibold text-slate-300">
                        No active alerts in queue
                      </span>
                      <p className="text-[11px] text-slate-500 max-w-sm">
                        Alerts arrive through the authenticated webhooks (/api/webhooks/wazuh, /edr, /xdr).
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                recentAlerts.map((alert) => {
                  const desc = alert.raw_payload?.rule?.description || alert.rule_id;
                  return (
                    <tr key={alert.alert_id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3.5 px-4 font-mono font-bold text-white">
                        #{alert.alert_id}
                      </td>
                      <td className="py-3.5 px-4 max-w-xs truncate text-slate-200">
                        <span className="font-semibold block">{alert.rule_id}</span>
                        <span className="text-[11px] text-slate-400 truncate block">{desc}</span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`px-2 py-0.5 rounded-full border text-[11px] font-bold ${getSeverityBadge(alert.severity)}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`px-2 py-0.5 rounded-full border text-[11px] font-bold ${getStatusBadge(alert.status)}`}>
                          {alert.status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-slate-300">
                            {alert.ioc_count || 0} Artifacts
                          </span>
                          {(alert.max_threat_score || 0) > 0 && (
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-500/10 text-rose-400 font-mono font-bold">
                              TIP: {alert.max_threat_score}/100
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                        {alert.source}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => openInvestigate(alert.alert_id)}
                          className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600 text-blue-300 hover:text-white border border-blue-500/30 rounded-lg text-xs font-semibold transition"
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Investigate Modal */}
      <InvestigateModal
        alertId={selectedAlertId}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onAlertUpdated={loadData}
      />
    </div>
  );
}
