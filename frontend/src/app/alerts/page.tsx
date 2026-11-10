"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { 
  ShieldAlert, 
  Search, 
  Download, 
  Clock, 
  RefreshCw, 
  Filter,
  CheckCircle2, 
  AlertTriangle,
  ArrowRight,
  Layers,
  X
} from "lucide-react";
import { Alert } from "@/lib/types";
import { api } from "@/lib/api";
import InvestigateModal from "@/components/InvestigateModal";

function AlertsContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  
  const initialStatusParam = searchParams.get("status") || "ALL";

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filteredAlerts, setFilteredAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>(
    initialStatusParam.toLowerCase() === "unresolved" ? "Unresolved" :
    initialStatusParam.toLowerCase() === "review" ? "Unresolved" :
    initialStatusParam.toUpperCase() === "ALL" ? "ALL" :
    initialStatusParam.charAt(0).toUpperCase() + initialStatusParam.slice(1).toLowerCase()
  );

  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const data = await api.getAlerts({ limit: 100 });
      setAlerts(data || []);
    } catch (err) {
      console.error("Failed to fetch alerts from SOAR backend:", err);
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  // Sync state if URL query param changes
  useEffect(() => {
    const sParam = searchParams.get("status");
    if (sParam) {
      if (sParam.toLowerCase() === "unresolved" || sParam.toLowerCase() === "review") {
        setStatusFilter("Unresolved");
      } else {
        setStatusFilter(sParam.charAt(0).toUpperCase() + sParam.slice(1).toLowerCase());
      }
    }
  }, [searchParams]);

  // Real-time filtering
  useEffect(() => {
    let result = [...alerts];

    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (a) =>
          a.rule_id.toLowerCase().includes(q) ||
          String(a.alert_id).includes(q) ||
          a.source.toLowerCase().includes(q) ||
          JSON.stringify(a.raw_payload || {}).toLowerCase().includes(q)
      );
    }

    if (severityFilter !== "ALL") {
      result = result.filter((a) => a.severity.toLowerCase() === severityFilter.toLowerCase());
    }

    if (statusFilter !== "ALL") {
      if (statusFilter.toLowerCase() === "unresolved") {
        result = result.filter((a) => !["resolved", "closed"].includes(a.status.toLowerCase()));
      } else if (statusFilter.toLowerCase() === "review") {
        result = result.filter((a) => ["triaged", "new"].includes(a.status.toLowerCase()));
      } else {
        result = result.filter((a) => a.status.toLowerCase() === statusFilter.toLowerCase());
      }
    }

    setFilteredAlerts(result);
  }, [alerts, search, severityFilter, statusFilter]);

  const handleInvestigateClick = (alertId: number) => {
    setSelectedAlertId(alertId);
    setIsModalOpen(true);
  };

  const clearFilters = () => {
    setSearch("");
    setSeverityFilter("ALL");
    setStatusFilter("ALL");
    router.replace("/alerts");
  };

  const getSeverityBadgeClass = (severity?: string) => {
    switch (severity?.toLowerCase()) {
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

  const getStatusBadgeClass = (status?: string) => {
    switch (status?.toLowerCase()) {
      case "contained":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "monitoring":
        return "bg-blue-500/10 text-blue-400 border-blue-500/30";
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
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2.5">
            <h1 className="text-2xl font-black text-white tracking-tight">
              Alerts & Incident Investigation Workspace
            </h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-bold">
              {filteredAlerts.length} Active Cases
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Real-time incident ingestion, Multi-TIP consensus, NVD vulnerability guidance, and HITL/HOTL containment.
          </p>
        </div>

        <button
          onClick={fetchAlerts}
          className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 transition"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh Queue</span>
        </button>
      </div>

      {/* Query Banner if filtered by Review Gate / Unresolved */}
      {statusFilter === "Unresolved" && (
        <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-semibold flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0" />
            <span>
              <strong>Review Gate Active:</strong> Displaying unresolved cases awaiting analyst investigation, triage, or containment sign-off.
            </span>
          </div>
          <button
            onClick={clearFilters}
            className="text-xs text-amber-400 hover:text-white underline font-bold ml-4"
          >
            Show All Alerts
          </button>
        </div>
      )}

      {/* Filters Toolbar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4 shadow-lg">
        <div className="relative flex-1 max-w-md">
          <Search className="h-4 w-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search by Alert ID, Rule ID, host, or CVE..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-slate-500 text-[11px] font-bold uppercase mr-1">Severity:</span>
          {["ALL", "Critical", "High", "Medium", "Low"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded-md text-[11px] font-bold transition ${
                severityFilter === sev
                  ? "bg-blue-600 text-white"
                  : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-slate-500 text-[11px] font-bold uppercase mr-1">Status:</span>
          {["ALL", "Unresolved", "New", "Triaged", "Contained", "Resolved"].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded-md text-[11px] font-bold transition ${
                statusFilter === st
                  ? "bg-indigo-600 text-white"
                  : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Main Alerts Data Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 font-bold uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3.5 px-4">Case #</th>
                <th className="py-3.5 px-4">Rule & Detection Telemetry</th>
                <th className="py-3.5 px-4">Severity</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">IoCs & Intel Score</th>
                <th className="py-3.5 px-4">Ingested At</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-16 text-center text-slate-400">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500" />
                      <span>Loading alert telemetry from SOAR pipeline...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-16 text-center text-slate-400">
                    <div className="flex flex-col items-center justify-center space-y-3">
                      <div className="h-12 w-12 rounded-2xl bg-slate-800/70 border border-slate-700/60 flex items-center justify-center text-slate-400">
                        <ShieldAlert className="h-6 w-6 text-slate-400" />
                      </div>
                      <span className="text-sm font-semibold text-slate-300">
                        {statusFilter !== "ALL" || severityFilter !== "ALL" || search
                          ? "No cases match the active filter criteria."
                          : "No active security cases in queue."}
                      </span>
                      <p className="text-xs text-slate-500 max-w-sm">
                        {statusFilter !== "ALL" || severityFilter !== "ALL" || search
                          ? "Try clearing filters to view all telemetry events."
                          : "The SOAR system is listening for live SIEM, EDR, and Suricata telemetry."}
                      </p>
                      {(statusFilter !== "ALL" || severityFilter !== "ALL" || search) && (
                        <button
                          onClick={clearFilters}
                          className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 rounded-lg text-xs font-semibold transition"
                        >
                          Clear Active Filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr
                    key={alert.alert_id}
                    onClick={() => handleInvestigateClick(alert.alert_id)}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-4 px-4 font-mono font-bold text-blue-400">
                      #{alert.alert_id}
                    </td>
                    <td className="py-4 px-4 max-w-md">
                      <div className="font-bold text-white tracking-wide truncate">
                        {alert.rule_id}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">
                        {alert.raw_payload?.rule?.description || alert.raw_payload?.full_log || "Wazuh detection match"}
                      </div>
                    </td>
                    <td className="py-4 px-4">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getSeverityBadgeClass(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-4 px-4">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getStatusBadgeClass(alert.status)}`}>
                        {alert.status}
                      </span>
                    </td>
                    <td className="py-4 px-4">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-slate-300">
                          {alert.ioc_count || 0} Artifacts
                        </span>
                        {(alert.max_threat_score || 0) > 0 && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-500/10 text-rose-400 font-mono font-bold">
                            Score: {alert.max_threat_score}/100
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-4 px-4 text-slate-400 font-mono text-[11px]">
                      {alert.created_at ? new Date(alert.created_at).toLocaleString() : "Live Telemetry"}
                    </td>
                    <td className="py-4 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => handleInvestigateClick(alert.alert_id)}
                        className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold shadow-md shadow-blue-600/20 transition transform hover:-translate-y-0.5"
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
      </div>

      {/* Shared Single-Pane-of-Glass Investigation Modal (No Excessive Scrolling) */}
      <InvestigateModal
        alertId={selectedAlertId}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onAlertUpdated={fetchAlerts}
      />
    </div>
  );
}

export default function AlertsPage() {
  return (
    <Suspense fallback={
      <div className="flex flex-col items-center justify-center py-24 space-y-3">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
        <p className="text-sm text-slate-400">Loading investigation workspace...</p>
      </div>
    }>
      <AlertsContent />
    </Suspense>
  );
}
