"use client";

import React, { useState, useEffect } from "react";
import { 
  X, 
  ShieldAlert, 
  CheckCircle2, 
  XCircle, 
  Download, 
  ExternalLink, 
  Cpu, 
  Terminal, 
  Clock, 
  Radio, 
  FileText,
  AlertTriangle,
  Lock,
  Layers,
  Sparkles,
  Eye,
  Zap,
  RefreshCw,
  Copy,
  Check,
  Globe,
  Database,
  ShieldCheck,
  ShieldX
} from "lucide-react";
import { AlertDetail, IocArtifact } from "@/lib/types";
import { api } from "@/lib/api";

interface InvestigateModalProps {
  alertId: number | null;
  isOpen: boolean;
  onClose: () => void;
  onAlertUpdated?: () => void;
}

export default function InvestigateModal({
  alertId,
  isOpen,
  onClose,
  onAlertUpdated,
}: InvestigateModalProps) {
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [vulnIntel, setVulnIntel] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"context" | "multitip" | "nvd" | "playbooks" | "timeline">("context");
  const [copiedPayload, setCopiedPayload] = useState<boolean>(false);

  const fetchAlertDetail = async (id: number) => {
    setLoading(true);
    setError(null);
    try {
      const [data, vIntel] = await Promise.allSettled([
        api.getAlertDetail(id),
        api.getAlertVulnerabilities(id)
      ]);
      if (data.status === "fulfilled") {
        setDetail(data.value);
      } else {
        throw new Error("Failed to load alert details.");
      }
      if (vIntel.status === "fulfilled") {
        setVulnIntel(vIntel.value);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load alert details.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && alertId) {
      setActiveTab("context");
      fetchAlertDetail(alertId);
    } else {
      setDetail(null);
      setVulnIntel(null);
    }
  }, [isOpen, alertId]);

  if (!isOpen || !alertId) return null;

  const handleApprove = async () => {
    if (!detail) return;
    setActionLoading(true);
    try {
      await api.approveAlert(detail.alert_id);
      await fetchAlertDetail(detail.alert_id);
      if (onAlertUpdated) onAlertUpdated();
    } catch (err: any) {
      alert("Error approving alert: " + err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleDismiss = async () => {
    if (!detail) return;
    setActionLoading(true);
    try {
      await api.dismissAlert(detail.alert_id);
      await fetchAlertDetail(detail.alert_id);
      if (onAlertUpdated) onAlertUpdated();
    } catch (err: any) {
      alert("Error dismissing alert: " + err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleLowTicketKeep = async () => {
    if (!detail) return;
    setActionLoading(true);
    try {
      await api.submitAlertDecision(detail.alert_id, "keep_and_monitor", "Analyst confirmed monitoring for low-risk activity.");
      await fetchAlertDetail(detail.alert_id);
      if (onAlertUpdated) onAlertUpdated();
    } catch (err: any) {
      alert("Error keeping alert: " + err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleLowTicketTakeAction = async () => {
    if (!detail) return;
    setActionLoading(true);
    try {
      await api.submitAlertDecision(detail.alert_id, "take_action", "Analyst escalated and executed containment on low-severity ticket.");
      await fetchAlertDetail(detail.alert_id);
      if (onAlertUpdated) onAlertUpdated();
    } catch (err: any) {
      alert("Error executing action: " + err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleExecuteNvdHotl = async () => {
    if (!detail) return;
    setActionLoading(true);
    try {
      await api.executeNvdHotl(detail.alert_id);
      await fetchAlertDetail(detail.alert_id);
      if (onAlertUpdated) onAlertUpdated();
    } catch (err: any) {
      alert("Error executing NVD HOTL containment: " + err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleBackgroundTipEnrich = async () => {
    if (!detail) return;
    setActionLoading(true);
    try {
      await api.triggerBackgroundTipEnrichment(detail.alert_id);
      setTimeout(async () => {
        await fetchAlertDetail(detail.alert_id);
        if (onAlertUpdated) onAlertUpdated();
      }, 1500);
    } catch (err: any) {
      alert("Error dispatching Multi-TIP enrichment: " + err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const copyPayload = () => {
    if (!detail?.raw_payload) return;
    navigator.clipboard.writeText(JSON.stringify(detail.raw_payload, null, 2));
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
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

  const isLowTicket = detail?.severity?.toLowerCase() === "low";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/85 backdrop-blur-md animate-fade-in">
      <div 
        className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-7xl h-[88vh] max-h-[92vh] flex flex-col shadow-2xl shadow-black overflow-hidden relative"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Header Bar */}
        <div className="p-4 px-6 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center space-x-3 overflow-hidden">
            <div className="h-9 w-9 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
              <ShieldAlert className="h-5 w-5 text-blue-400" />
            </div>
            <div className="overflow-hidden">
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white tracking-wide truncate">
                  Investigation Case #{alertId} {detail ? `— ${detail.rule_id}` : ""}
                </h2>
                {detail && (
                  <>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold ${getSeverityBadge(detail.severity)}`}>
                      {detail.severity}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full border font-bold ${getStatusBadge(detail.status)}`}>
                      {detail.status}
                    </span>
                  </>
                )}
              </div>
              <p className="text-[11px] text-slate-400 font-mono truncate">
                Ingested: {detail?.created_at ? new Date(detail.created_at).toUTCString() : "Live Telemetry"} | Source: {detail?.source || "Wazuh SIEM"}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <a
              href={api.getReportDownloadUrl(alertId)}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition"
              title="Download Executive Incident PDF Report"
            >
              <Download className="h-3.5 w-3.5 text-blue-400" />
              <span className="hidden sm:inline">PDF Report</span>
            </a>

            <button
              onClick={onClose}
              className="h-8 w-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition border border-slate-700"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Main Single-Pane Workbench Body (CSS Grid: Sticky Sidebar + Tabbed Navigation) */}
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 overflow-hidden min-h-0">
          
          {/* ===================================================================== */}
          {/* LEFT STICKY SIDEBAR (4 Cols) — Action Center & Summary (Zero Scrolling) */}
          {/* ===================================================================== */}
          <div className="lg:col-span-4 bg-slate-950/70 border-r border-slate-800/80 p-5 flex flex-col justify-between overflow-y-auto space-y-4">
            <div className="space-y-4">
              
              {/* Multi-TIP Consensus Score Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
                <div className="flex items-center justify-between text-xs text-slate-400 font-bold uppercase tracking-wider mb-2">
                  <span>Worst-Case TIP Intel</span>
                  <Layers className="h-3.5 w-3.5 text-blue-400" />
                </div>
                <div className="flex items-baseline space-x-2">
                  <span className={`text-3xl font-black ${
                    (detail?.max_threat_score || 0) >= 50 ? "text-rose-400" :
                    (detail?.max_threat_score || 0) > 0 ? "text-amber-400" : "text-emerald-400"
                  }`}>
                    {detail?.max_threat_score ?? 0}
                  </span>
                  <span className="text-xs text-slate-500 font-bold">/ 100</span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded ml-auto ${
                    (detail?.max_threat_score || 0) >= 50 ? "bg-rose-500/10 text-rose-400 border border-rose-500/20" :
                    (detail?.max_threat_score || 0) > 0 ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                    "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                  }`}>
                    {(detail?.max_threat_score || 0) >= 50 ? "Malicious" : (detail?.max_threat_score || 0) > 0 ? "Suspicious" : "Clean"}
                  </span>
                </div>

                <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
                  <span>Aggregated Sources:</span>
                  <span className="font-semibold text-slate-200">VT v3 + OTX + AbuseIPDB</span>
                </div>
              </div>

              {/* Case Metadata */}
              <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4 text-xs space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-400">Assigned Operator:</span>
                  <span className="font-semibold text-slate-200">{detail?.assigned_analyst || "SOC Tier 1 Queue"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Resolved By:</span>
                  <span className="font-semibold text-purple-400">{detail?.resolved_by || "Pending Verification"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Affected Asset:</span>
                  <span className="font-mono text-blue-300">
                    {detail?.raw_payload?.agent?.name || detail?.raw_payload?.agent?.ip || "Local Subnet"}
                  </span>
                </div>
                {detail?.analyst_decision && (
                  <div className="pt-2 border-t border-slate-800 text-[11px] text-emerald-400 font-semibold flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5 flex-shrink-0" />
                    <span className="truncate">{detail.analyst_decision}</span>
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK Pills */}
              <div>
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
                  MITRE ATT&CK Matrix
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {(detail?.mitre_attack?.id || ["T1046"]).map((tid: string, idx: number) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300 text-[11px] font-mono font-bold"
                    >
                      {tid} • {detail?.mitre_attack?.technique?.[idx] || detail?.mitre_attack?.tactic?.[idx] || "Active"}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* ACTION CENTER PANEL (ALWAYS VISIBLE AT BOTTOM OF SIDEBAR WITHOUT SCROLLING) */}
            <div className="pt-3 border-t border-slate-800 space-y-2">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">
                Response Actions
              </span>

              {/* 1. Low Ticket Decision Buttons */}
              {isLowTicket && detail?.status !== "Contained" && detail?.status !== "Closed" && (
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={handleLowTicketKeep}
                    disabled={actionLoading}
                    className="py-2 px-2.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/40 text-xs font-bold transition flex items-center justify-center space-x-1 disabled:opacity-50"
                  >
                    <Eye className="h-3.5 w-3.5" />
                    <span>Keep & Monitor</span>
                  </button>

                  <button
                    onClick={handleLowTicketTakeAction}
                    disabled={actionLoading}
                    className="py-2 px-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold shadow-md shadow-amber-600/25 transition flex items-center justify-center space-x-1 disabled:opacity-50"
                  >
                    <Zap className="h-3.5 w-3.5" />
                    <span>Take Action</span>
                  </button>
                </div>
              )}

              {/* 2. Standard HITL Sign-off (Triaged Alerts) */}
              {!isLowTicket && detail?.status === "Triaged" && (
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={handleDismiss}
                    disabled={actionLoading}
                    className="py-2 px-2.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/40 text-xs font-bold transition flex items-center justify-center space-x-1 disabled:opacity-50"
                  >
                    <XCircle className="h-3.5 w-3.5" />
                    <span>Deny / Dismiss</span>
                  </button>

                  <button
                    onClick={handleApprove}
                    disabled={actionLoading}
                    className="py-2 px-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-md shadow-emerald-600/25 transition flex items-center justify-center space-x-1 disabled:opacity-50"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    <span>Approve Contain</span>
                  </button>
                </div>
              )}

              {/* 3. NVD HOTL Autonomous Action Button */}
              {vulnIntel?.hotl_autonomous_policy?.eligible_for_hotl && detail?.status !== "Contained" && (
                <button
                  onClick={handleExecuteNvdHotl}
                  disabled={actionLoading}
                  className="w-full py-2 px-3 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold shadow-md shadow-rose-600/25 transition flex items-center justify-center space-x-1.5 disabled:opacity-50"
                >
                  <ShieldAlert className="h-3.5 w-3.5" />
                  <span>Execute NVD HOTL Auto-Isolation</span>
                </button>
              )}

              {/* 4. Background TIP Refresh */}
              <button
                onClick={handleBackgroundTipEnrich}
                disabled={actionLoading}
                className="w-full py-1.5 px-3 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 text-xs font-medium transition flex items-center justify-center space-x-1.5"
              >
                <RefreshCw className={`h-3 w-3 ${actionLoading ? "animate-spin text-blue-400" : ""}`} />
                <span>Background Multi-TIP Re-Enrich</span>
              </button>
            </div>
          </div>

          {/* ===================================================================== */}
          {/* RIGHT MAIN VIEW (8 Cols) — Tabbed Single-Pane Workbench               */}
          {/* ===================================================================== */}
          <div className="lg:col-span-8 flex flex-col overflow-hidden bg-slate-900 min-h-0">
            {/* Navigation Tabs Header */}
            <div className="px-5 pt-3 border-b border-slate-800 bg-slate-950/40 flex items-center space-x-2 flex-shrink-0">
              {[
                { id: "context", label: "Context & AI", icon: Sparkles },
                { id: "multitip", label: "Multi-TIP Intel", icon: Layers },
                { id: "nvd", label: "NVD Vulnerabilities", icon: ShieldAlert, badge: vulnIntel?.cves_detected?.length ? String(vulnIntel.cves_detected.length) : undefined },
                { id: "playbooks", label: "Playbooks & HOTL", icon: Cpu },
                { id: "timeline", label: "Timeline & Audit", icon: Clock },
              ].map((tab) => {
                const TabIcon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`flex items-center space-x-2 px-3.5 py-2.5 rounded-t-lg text-xs font-bold border-b-2 transition ${
                      isActive
                        ? "border-blue-500 text-blue-400 bg-slate-900"
                        : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
                    }`}
                  >
                    <TabIcon className="h-3.5 w-3.5" />
                    <span>{tab.label}</span>
                    {tab.badge && (
                      <span className="text-[10px] bg-rose-500/20 text-rose-400 px-1.5 py-0.2 rounded-full font-bold">
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Tabbed Content Body with Viewport Fit (No Excessive Scrolling) */}
            <div className="flex-1 p-5 overflow-y-auto space-y-4 min-h-0">
              {loading ? (
                <div className="flex flex-col items-center justify-center py-20 space-y-3">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
                  <p className="text-sm text-slate-400">Loading incident telemetry & intelligence...</p>
                </div>
              ) : error ? (
                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm">
                  {error}
                </div>
              ) : detail ? (
                <>
                  {/* TAB 1: CONTEXT & AI */}
                  {activeTab === "context" && (
                    <div className="space-y-4">
                      {/* AI Executive Summary Card */}
                      <div className="p-4 rounded-xl bg-gradient-to-r from-blue-950/40 via-indigo-950/30 to-slate-900 border border-blue-500/30">
                        <div className="flex items-center space-x-2 text-blue-400 text-xs font-bold uppercase tracking-wider mb-2">
                          <Sparkles className="h-4 w-4" />
                          <span>AI Triage & Contextual Analysis</span>
                        </div>
                        <p className="text-sm text-slate-200 leading-relaxed font-sans">
                          {detail.ai_summary || "Automated triage executed. Indicators matched high threat parameters."}
                        </p>
                      </div>

                      {/* Rule & Detection Details */}
                      <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 space-y-2">
                        <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-1">
                          Rule Identification
                        </span>
                        <div className="text-xs text-slate-300">
                          <span className="font-semibold text-white">Rule ID:</span> {detail.rule_id}
                        </div>
                        <div className="text-xs text-slate-300">
                          <span className="font-semibold text-white">Description:</span>{" "}
                          {detail.raw_payload?.rule?.description || "Wazuh Agent Detection"}
                        </div>
                      </div>

                      {/* Raw Telemetry Payload Viewer */}
                      <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
                        <div className="px-4 py-2 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
                          <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                            <Terminal className="h-3.5 w-3.5 text-blue-400" />
                            raw_telemetry_payload.json
                          </span>
                          <button
                            onClick={copyPayload}
                            className="text-xs text-slate-400 hover:text-white flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 transition"
                          >
                            {copiedPayload ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                            <span>{copiedPayload ? "Copied" : "Copy JSON"}</span>
                          </button>
                        </div>
                        <pre className="p-4 text-xs font-mono text-slate-300 overflow-x-auto max-h-72 select-all leading-tight">
                          {JSON.stringify(detail.raw_payload || {}, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* TAB 2: MULTI-TIP INTEL */}
                  {activeTab === "multitip" && (
                    <div className="space-y-4">
                      {/* TIP Providers Summary Bar */}
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
                          <div className="flex items-center space-x-2 text-blue-400 text-xs font-bold mb-1">
                            <Globe className="h-3.5 w-3.5" />
                            <span>VirusTotal v3</span>
                          </div>
                          <p className="text-xs text-slate-400">File hash & URL reputation query active.</p>
                        </div>
                        <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
                          <div className="flex items-center space-x-2 text-indigo-400 text-xs font-bold mb-1">
                            <Database className="h-3.5 w-3.5" />
                            <span>AlienVault OTX</span>
                          </div>
                          <p className="text-xs text-slate-400">Threat pulse & pulse subscribers cross-checked.</p>
                        </div>
                        <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
                          <div className="flex items-center space-x-2 text-emerald-400 text-xs font-bold mb-1">
                            <ShieldAlert className="h-3.5 w-3.5" />
                            <span>AbuseIPDB / ThreatFox</span>
                          </div>
                          <p className="text-xs text-slate-400">Confidence score & malware family correlation.</p>
                        </div>
                      </div>

                      {/* IoC Artifacts Table */}
                      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                        <div className="p-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                          <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                            <Layers className="h-3.5 w-3.5 text-blue-400" />
                            Extracted IoC Artifacts ({detail.ioc_artifacts.length})
                          </span>
                        </div>
                        {detail.ioc_artifacts.length === 0 ? (
                          <div className="p-6 text-center text-xs text-slate-500 italic">
                            No explicit IoCs extracted from current alert telemetry.
                          </div>
                        ) : (
                          <div className="divide-y divide-slate-800">
                            {detail.ioc_artifacts.map((ioc: IocArtifact) => {
                              const isMalicious = ioc.threat_score >= 50;
                              const isSuspicious = ioc.threat_score > 0 && ioc.threat_score < 50;
                              return (
                                <div key={ioc.artifact_id} className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-900/50">
                                  <div className="space-y-1">
                                    <div className="flex items-center space-x-2">
                                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                                        {ioc.artifact_type}
                                      </span>
                                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                                        isMalicious 
                                          ? "bg-rose-500/20 text-rose-400 border border-rose-500/30" 
                                          : isSuspicious
                                          ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                                          : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                                      }`}>
                                        {isMalicious ? "Malicious" : isSuspicious ? "Suspicious" : "Clean"}
                                      </span>
                                    </div>
                                    <div className="font-mono text-xs text-slate-200 select-all break-all">
                                      {ioc.value}
                                    </div>
                                  </div>
                                  <div className="flex items-center space-x-3 sm:text-right flex-shrink-0">
                                    <div>
                                      <div className="text-xs font-bold font-mono text-white">{ioc.threat_score}/100</div>
                                      <div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden mt-1">
                                        <div 
                                          className={`h-full rounded-full ${
                                            isMalicious ? "bg-rose-500" : isSuspicious ? "bg-amber-500" : "bg-emerald-500"
                                          }`}
                                          style={{ width: `${Math.max(5, ioc.threat_score)}%` }}
                                        />
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* TAB 3: NVD VULNERABILITIES */}
                  {activeTab === "nvd" && (
                    <div className="space-y-4">
                      {vulnIntel ? (
                        <>
                          {/* NVD Match Banner */}
                          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                            <div>
                              <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                                NIST NVD CVE Correlation
                              </span>
                              <div className="text-lg font-black text-white mt-0.5">
                                {vulnIntel.cves_detected?.length ? vulnIntel.cves_detected.join(", ") : "No Direct CVE Matched"}
                              </div>
                            </div>
                            <div className="text-right">
                              <span className="text-xs text-slate-400 block">CVSS v3.1 Severity</span>
                              <span className={`text-xl font-black ${
                                (vulnIntel.cvss_max_score || 0) >= 9.0 ? "text-rose-400" :
                                (vulnIntel.cvss_max_score || 0) >= 7.0 ? "text-orange-400" : "text-amber-400"
                              }`}>
                                {vulnIntel.cvss_max_score || "N/A"}
                              </span>
                            </div>
                          </div>

                          {/* HITL Remediation Guidance */}
                          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                            <span className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                              <ShieldCheck className="h-4 w-4" />
                              HITL Remediation Advice (Human in the Loop)
                            </span>
                            <p className="text-xs text-slate-200 leading-relaxed font-sans">
                              {vulnIntel.hitl_remediation_advice || "Review host network access, ensure latest patch levels are applied, and verify firewall rule enforcement."}
                            </p>
                          </div>

                          {/* HOTL Autonomous Containment Policy */}
                          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                            <span className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                              <Zap className="h-4 w-4" />
                              HOTL Autonomous Policy (Human out of the Loop)
                            </span>
                            <div className="text-xs text-slate-300">
                              <span className="font-semibold text-white">Status:</span>{" "}
                              {vulnIntel.hotl_autonomous_policy?.eligible_for_hotl 
                                ? "Auto-Isolation Permitted (CVSS Critical Threshold Exceeded)" 
                                : "HITL Sign-Off Required Prior to Execution"}
                            </div>
                            <p className="text-xs text-slate-400 leading-relaxed">
                              {vulnIntel.hotl_autonomous_policy?.action_description || "Standard automated playbook triggers upon threshold violation."}
                            </p>
                          </div>
                        </>
                      ) : (
                        <div className="p-6 text-center text-xs text-slate-500 italic">
                          No NVD vulnerability correlation records returned for this alert.
                        </div>
                      )}
                    </div>
                  )}

                  {/* TAB 4: PLAYBOOKS & HOTL */}
                  {activeTab === "playbooks" && (
                    <div className="space-y-4">
                      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                        <div className="p-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                          <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                            <Cpu className="h-3.5 w-3.5 text-blue-400" />
                            Triggered Automated Playbooks
                          </span>
                        </div>
                        {detail.playbook_executions.length === 0 ? (
                          <div className="p-6 text-center text-xs text-slate-500 italic">
                            No playbook executions recorded for this alert.
                          </div>
                        ) : (
                          <div className="divide-y divide-slate-800">
                            {detail.playbook_executions.map((exec) => (
                              <div key={exec.execution_id} className="p-3.5 flex items-center justify-between hover:bg-slate-900/50">
                                <div className="space-y-1">
                                  <div className="text-xs font-bold text-white flex items-center gap-2">
                                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                                    <span>{exec.playbook_name || "SOAR IR Playbook"}</span>
                                  </div>
                                  <div className="text-[11px] text-slate-400 font-mono">
                                    Executed: {exec.executed_at ? new Date(exec.executed_at).toLocaleTimeString() : "Autonomous"}
                                  </div>
                                </div>
                                <div className="text-right">
                                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    {exec.status}
                                  </span>
                                  {exec.mttr_seconds > 0 && (
                                    <div className="text-[11px] text-emerald-400 font-bold font-mono mt-1">
                                      MTTR: {exec.mttr_seconds.toFixed(2)}s
                                    </div>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* TAB 5: TIMELINE & AUDIT */}
                  {activeTab === "timeline" && (
                    <div className="space-y-4">
                      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                        <div className="p-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                          <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                            <Clock className="h-3.5 w-3.5 text-indigo-400" />
                            Containment Actions & Analyst Audit Trail
                          </span>
                        </div>
                        {detail.containment_actions.length === 0 ? (
                          <div className="p-6 text-center text-xs text-slate-500 italic">
                            No containment actions or audit logs recorded for this alert yet.
                          </div>
                        ) : (
                          <div className="divide-y divide-slate-800">
                            {detail.containment_actions.map((act) => (
                              <div key={act.action_id} className="p-3.5 flex items-center justify-between hover:bg-slate-900/50">
                                <div className="flex items-center space-x-3">
                                  <Lock className="h-4 w-4 text-emerald-400 flex-shrink-0" />
                                  <div>
                                    <div className="text-xs font-mono font-bold text-slate-200">{act.action_type}</div>
                                    <div className="text-[10px] text-slate-500">
                                      Executed By: {act.executed_by || "SOAR Autonomous Core"}
                                    </div>
                                  </div>
                                </div>
                                <div className="text-right">
                                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    {act.status}
                                  </span>
                                  <div className="text-[10px] text-slate-400 mt-1 font-mono">
                                    {new Date(act.timestamp).toLocaleTimeString()}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </>
              ) : null}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
