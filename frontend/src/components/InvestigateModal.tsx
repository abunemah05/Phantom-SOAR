"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  X,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Download,
  Cpu,
  Terminal,
  Clock,
  AlertTriangle,
  Layers,
  ClipboardList,
  Eye,
  Zap,
  RefreshCw,
  Copy,
  Check,
  ShieldCheck,
  FlaskConical,
  ChevronDown,
  ChevronRight,
  AlertCircle,
  ScrollText
} from "lucide-react";
import {
  AlertDetail,
  ContainmentAction,
  IocArtifact,
  TipProviderResult,
  VulnerabilityIntel
} from "@/lib/types";
import { api } from "@/lib/api";
import { formatDuration } from "@/lib/format";

interface InvestigateModalProps {
  alertId: number | null;
  isOpen: boolean;
  onClose: () => void;
  onAlertUpdated?: () => void;
}

type TabId = "context" | "intel" | "nvd" | "response" | "timeline";

// --- Presentation helpers --------------------------------------------------

const PROVIDER_LABELS: Record<string, string> = {
  virustotal: "VirusTotal",
  alienvault_otx: "AlienVault OTX",
  otx: "AlienVault OTX",
  abuseipdb: "AbuseIPDB",
  threatfox: "ThreatFox",
};

const PROVIDER_STATUS: Record<string, { label: string; className: string; hint: string }> = {
  live: {
    label: "Live",
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    hint: "Answered by the provider's live API.",
  },
  not_found: {
    label: "Not found",
    className: "bg-slate-700/30 text-slate-300 border-slate-600/40",
    hint: "The provider has no record of this indicator. That means no known reputation, not that it is malicious.",
  },
  not_configured: {
    label: "Not configured",
    className: "bg-slate-800 text-slate-400 border-slate-700",
    hint: "No API key is configured for this provider.",
  },
  error: {
    label: "Error",
    className: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    hint: "The lookup failed (network, quota or authentication error).",
  },
  lab_fixture: {
    label: "Lab fixture",
    className: "bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/30",
    hint: "Simulation mode: a fixed lab value for a documentation-range IP or demo IOC, not a real lookup.",
  },
  skipped: {
    label: "Skipped",
    className: "bg-slate-800 text-slate-400 border-slate-700",
    hint: "Not looked up (private/reserved address or unsupported indicator type).",
  },
};

const VERDICT_CLASS: Record<string, string> = {
  malicious: "bg-rose-500/20 text-rose-400 border-rose-500/30",
  suspicious: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  clean: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  unknown: "bg-slate-700/40 text-slate-300 border-slate-600/50",
};

const VERDICT_RANK: Record<string, number> = { malicious: 3, suspicious: 2, clean: 1, unknown: 0 };

const ENRICHMENT_LABELS: Record<string, { label: string; className: string }> = {
  enriched: { label: "Enriched", className: "text-emerald-400" },
  partial: { label: "Partially enriched", className: "text-amber-400" },
  unavailable: { label: "Enrichment unavailable", className: "text-rose-400" },
  not_configured: { label: "No TIP provider configured", className: "text-slate-400" },
  pending: { label: "Enrichment pending", className: "text-blue-400" },
};

const EXECUTION_MODE: Record<string, { label: string; className: string; hint: string }> = {
  live: {
    label: "LIVE",
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    hint: "A real API call was made to the connector.",
  },
  simulated: {
    label: "SIMULATED",
    className: "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/40",
    hint: "Connector not configured and simulation mode is on: nothing was changed on a real system.",
  },
  skipped: {
    label: "SKIPPED",
    className: "bg-slate-700/40 text-slate-300 border-slate-600/50",
    hint: "Connector not configured and simulation mode is off: the action was not performed.",
  },
  blocked: {
    label: "BLOCKED",
    className: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    hint: "The policy engine refused this action.",
  },
  failed: {
    label: "FAILED",
    className: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    hint: "The connector returned an error.",
  },
};

function providerLabel(key: string, p?: TipProviderResult): string {
  return PROVIDER_LABELS[key] || PROVIDER_LABELS[p?.provider || ""] || p?.provider || key;
}

function isProviderResult(value: unknown): value is TipProviderResult {
  return Boolean(value && typeof value === "object" && "status" in (value as Record<string, unknown>));
}

/** Per-provider results of an IOC: tip_results.providers, or a flat provider map for older records. */
function getProviders(ioc: IocArtifact): Array<[string, TipProviderResult]> {
  const tr = ioc.tip_results;
  if (!tr || typeof tr !== "object") return [];
  const source = tr.providers && typeof tr.providers === "object" ? tr.providers : tr;
  return Object.entries(source).filter((entry): entry is [string, TipProviderResult] => isProviderResult(entry[1]));
}

function providerHasScore(p: TipProviderResult): boolean {
  return (p.status === "live" || p.status === "lab_fixture") && typeof p.threat_score === "number";
}

function iocHasEvidence(ioc: IocArtifact): boolean {
  return getProviders(ioc).some(([, p]) => providerHasScore(p));
}

function verdictOf(ioc: IocArtifact): string {
  return ioc.verdict || "Unknown";
}

function VerdictBadge({ verdict }: { verdict: string }) {
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${VERDICT_CLASS[verdict.toLowerCase()] || VERDICT_CLASS.unknown}`}>
      {verdict}
    </span>
  );
}

function ExecutionModeBadge({ mode }: { mode?: string | null }) {
  const meta = mode ? EXECUTION_MODE[mode.toLowerCase()] : undefined;
  if (!meta) {
    return (
      <span
        className="px-2 py-0.5 rounded text-[10px] font-bold font-mono border bg-slate-800 text-slate-400 border-slate-700"
        title="Recorded before execution modes were tracked."
      >
        {mode ? mode.toUpperCase() : "UNRECORDED"}
      </span>
    );
  }
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${meta.className}`} title={meta.hint}>
      {meta.label}
    </span>
  );
}

function formatSummaryValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.length ? value.map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join(", ") : "none";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function stepsOf(workflowLogic: unknown): Array<Record<string, unknown>> {
  let logic = workflowLogic;
  if (typeof logic === "string") {
    try {
      logic = JSON.parse(logic);
    } catch {
      return [];
    }
  }
  const steps = (logic as { steps?: unknown })?.steps;
  return Array.isArray(steps) ? (steps as Array<Record<string, unknown>>) : [];
}

// --- Component ---------------------------------------------------------------

export default function InvestigateModal({
  alertId,
  isOpen,
  onClose,
  onAlertUpdated,
}: InvestigateModalProps) {
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [vulnIntel, setVulnIntel] = useState<VulnerabilityIntel | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("context");
  const [copiedPayload, setCopiedPayload] = useState<boolean>(false);
  const [expandedActions, setExpandedActions] = useState<Record<number, boolean>>({});

  const fetchAlertDetail = useCallback(async (id: number) => {
    setLoading(true);
    setError(null);
    try {
      const [data, vIntel] = await Promise.allSettled([
        api.getAlertDetail(id),
        api.getAlertVulnerabilities(id),
      ]);
      if (data.status !== "fulfilled") {
        throw data.reason instanceof Error ? data.reason : new Error("Failed to load alert details.");
      }
      setDetail(data.value);
      if (vIntel.status === "fulfilled") {
        setVulnIntel(vIntel.value);
      } else {
        setVulnIntel(data.value.vulnerability_intel ?? null);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load alert details.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen && alertId) {
      setActiveTab("context");
      setActionError(null);
      setActionNotice(null);
      setExpandedActions({});
      fetchAlertDetail(alertId);
    } else {
      setDetail(null);
      setVulnIntel(null);
    }
  }, [isOpen, alertId, fetchAlertDetail]);

  if (!isOpen || !alertId) return null;

  const runAction = async (label: string, fn: () => Promise<unknown>, successText?: string) => {
    if (!detail) return;
    setActionLoading(true);
    setActionError(null);
    setActionNotice(null);
    try {
      await fn();
      await fetchAlertDetail(detail.alert_id);
      if (successText) setActionNotice(successText);
      if (onAlertUpdated) onAlertUpdated();
    } catch (err: any) {
      setActionError(`${label} failed: ${err.message || "request failed"}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleApprove = () =>
    runAction("Approval", () => api.approveAlert(detail!.alert_id), "Containment approved. Check each action's execution mode in Response Actions.");
  const handleDismiss = () =>
    runAction("Dismissal", () => api.dismissAlert(detail!.alert_id), "Alert dismissed.");
  const handleLowTicketKeep = () =>
    runAction(
      "Keep & monitor",
      () => api.submitAlertDecision(detail!.alert_id, "keep_and_monitor", "Analyst confirmed monitoring for low-risk activity."),
      "Alert kept under monitoring."
    );
  const handleLowTicketTakeAction = () =>
    runAction(
      "Take action",
      () => api.submitAlertDecision(detail!.alert_id, "take_action", "Analyst escalated a low-severity alert for containment."),
      "Containment requested. Check each action's execution mode in Response Actions."
    );
  const handleExecuteNvdHotl = () =>
    runAction("NVD-recommended containment", () => api.executeNvdHotl(detail!.alert_id));

  const handleBackgroundTipEnrich = async () => {
    if (!detail) return;
    setActionLoading(true);
    setActionError(null);
    try {
      await api.triggerBackgroundTipEnrichment(detail.alert_id);
      setActionNotice("Re-enrichment queued. Results refresh shortly.");
      setTimeout(async () => {
        await fetchAlertDetail(detail.alert_id);
        if (onAlertUpdated) onAlertUpdated();
      }, 1500);
    } catch (err: any) {
      setActionError(`Re-enrichment failed: ${err.message || "request failed"}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleDownloadReport = async () => {
    setActionError(null);
    try {
      await api.downloadAlertReport(alertId);
    } catch (err: any) {
      setActionError(`PDF report unavailable: ${err.message || "request failed"}`);
    }
  };

  const copyPayload = () => {
    if (!detail?.raw_payload) return;
    navigator.clipboard.writeText(JSON.stringify(detail.raw_payload, null, 2));
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  const toggleAction = (id: number) =>
    setExpandedActions((prev) => ({ ...prev, [id]: !prev[id] }));

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

  // --- Derived state ---------------------------------------------------------
  const iocs = detail?.ioc_artifacts ?? [];
  const evidenceIocs = iocs.filter(iocHasEvidence);
  const worstVerdict = iocs.length
    ? iocs.map(verdictOf).reduce((a, b) => ((VERDICT_RANK[b.toLowerCase()] ?? 0) > (VERDICT_RANK[a.toLowerCase()] ?? 0) ? b : a), "Unknown")
    : null;
  const maxEvidenceScore = evidenceIocs.length ? Math.max(...evidenceIocs.map((i) => i.threat_score || 0)) : null;
  const providersWithEvidence = Array.from(
    new Set(
      iocs.flatMap((ioc) => getProviders(ioc).filter(([, p]) => providerHasScore(p)).map(([k, p]) => providerLabel(k, p)))
    )
  );
  const usedLabFixtures = iocs.some((ioc) => getProviders(ioc).some(([, p]) => p.status === "lab_fixture"));

  const actions = detail?.containment_actions ?? [];
  const simulatedActions = actions.filter((a) => (a.execution_mode || "").toLowerCase() === "simulated").length;

  const mitre = detail?.mitre_attack;
  const mitreIds = mitre?.id ?? [];

  const playbook = detail?.playbook ?? null;
  const playbookSteps = playbook ? stepsOf(playbook.workflow_logic) : [];
  const playbookMitre = (() => {
    if (!playbook) return null;
    const logic = typeof playbook.workflow_logic === "string" ? (() => { try { return JSON.parse(playbook.workflow_logic); } catch { return null; } })() : playbook.workflow_logic;
    return logic?.mitre_id || null;
  })();

  const isLowTicket = detail?.severity?.toLowerCase() === "low";
  const affectedAsset = detail?.raw_payload?.agent?.name || detail?.raw_payload?.agent?.ip || null;

  const timeline: Array<{ at: string; title: string; detail?: string; kind: string }> = detail
    ? [
        { at: detail.created_at, title: `Alert ingested from ${detail.source}`, detail: `${detail.rule_id} · severity ${detail.severity}`, kind: "ingest" },
        ...iocs.map((ioc) => ({
          at: ioc.created_at,
          title: `IOC ${ioc.artifact_type} ${ioc.value}`,
          detail: `Verdict ${verdictOf(ioc)} · ${ENRICHMENT_LABELS[ioc.enrichment_status || ""]?.label || ioc.enrichment_status || "enrichment status not recorded"}`,
          kind: "ioc",
        })),
        ...(detail.playbook_executions ?? []).map((ex) => ({
          at: ex.executed_at,
          title: `Playbook ${ex.playbook_name || `#${ex.playbook_id ?? "?"}`}: ${ex.status}`,
          detail: ex.mttr_seconds > 0 ? `MTTR ${formatDuration(ex.mttr_seconds)}` : undefined,
          kind: "playbook",
        })),
        ...actions.map((a) => ({
          at: a.timestamp,
          title: `${a.action_type}${a.target ? ` → ${a.target}` : ""}`,
          detail: `${(a.execution_mode || "unrecorded").toUpperCase()} · ${a.status} · by ${a.executed_by || "System"}`,
          kind: "action",
        })),
        ...(detail.resolved_at
          ? [{ at: detail.resolved_at, title: `Resolved by ${detail.resolved_by || "unknown"}`, detail: detail.analyst_decision, kind: "resolve" }]
          : []),
      ]
        .filter((e) => e.at)
        .sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime())
    : [];

  const renderActionRow = (act: ContainmentAction) => {
    const expanded = Boolean(expandedActions[act.action_id]);
    const hasDetails = act.details !== null && act.details !== undefined && !(typeof act.details === "object" && Object.keys(act.details as object).length === 0);
    return (
      <div key={act.action_id} className="hover:bg-slate-900/50">
        <button
          type="button"
          onClick={() => hasDetails && toggleAction(act.action_id)}
          className={`w-full p-3.5 flex items-center justify-between gap-3 text-left ${hasDetails ? "cursor-pointer" : "cursor-default"}`}
          title={hasDetails ? "Show connector response / policy details" : undefined}
        >
          <div className="flex items-start space-x-3 min-w-0">
            {hasDetails ? (
              expanded ? <ChevronDown className="h-4 w-4 text-slate-400 flex-shrink-0 mt-0.5" /> : <ChevronRight className="h-4 w-4 text-slate-400 flex-shrink-0 mt-0.5" />
            ) : (
              <span className="w-4 flex-shrink-0" />
            )}
            <div className="min-w-0">
              <div className="text-xs font-mono font-bold text-slate-200 truncate">{act.action_type}</div>
              <div className="text-[11px] text-slate-400 font-mono truncate">
                Target: <span className="text-slate-200">{act.target || "—"}</span>
                <span className="mx-1.5 text-slate-600">|</span>
                Connector: <span className="text-slate-200">{act.connector || "—"}</span>
              </div>
              <div className="text-[10px] text-slate-500">
                By {act.executed_by || "System"} · {formatTime(act.timestamp)}
              </div>
            </div>
          </div>
          <div className="text-right flex-shrink-0 space-y-1">
            <ExecutionModeBadge mode={act.execution_mode} />
            <div className="text-[10px] text-slate-400 font-semibold">{act.status}</div>
          </div>
        </button>
        {expanded && hasDetails && (
          <pre className="mx-3.5 mb-3.5 p-3 bg-slate-950 border border-slate-800 rounded-lg text-[11px] font-mono text-slate-300 overflow-x-auto max-h-60">
            {typeof act.details === "string" ? act.details : JSON.stringify(act.details, null, 2)}
          </pre>
        )}
      </div>
    );
  };

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
                    {detail.simulation_mode && (
                      <span
                        className="text-[10px] px-2 py-0.5 rounded-full border font-black bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/40 flex items-center gap-1"
                        title="Simulation mode is on: actions on unconfigured connectors are simulated."
                      >
                        <FlaskConical className="h-3 w-3" />
                        SIMULATION MODE
                      </span>
                    )}
                  </>
                )}
              </div>
              <p className="text-[11px] text-slate-400 font-mono truncate">
                Ingested: {detail?.created_at ? new Date(detail.created_at).toUTCString() : "—"} | Source: {detail?.source || "—"}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={handleDownloadReport}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition"
              title="Download the incident PDF report"
            >
              <Download className="h-3.5 w-3.5 text-blue-400" />
              <span className="hidden sm:inline">PDF Report</span>
            </button>

            <button
              onClick={onClose}
              className="h-8 w-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition border border-slate-700"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 overflow-hidden min-h-0">
          {/* LEFT SIDEBAR — summary and action center */}
          <div className="lg:col-span-4 bg-slate-950/70 border-r border-slate-800/80 p-5 flex flex-col justify-between overflow-y-auto space-y-4">
            <div className="space-y-4">
              {/* Threat-intel verdict card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
                <div className="flex items-center justify-between text-xs text-slate-400 font-bold uppercase tracking-wider mb-2">
                  <span>Threat Intel Verdict</span>
                  <Layers className="h-3.5 w-3.5 text-blue-400" />
                </div>
                {iocs.length === 0 ? (
                  <p className="text-xs text-slate-400">No IOCs were extracted from this alert.</p>
                ) : (
                  <>
                    <div className="flex items-baseline space-x-2">
                      {maxEvidenceScore !== null ? (
                        <>
                          <span className={`text-3xl font-black ${
                            maxEvidenceScore >= 70 ? "text-rose-400" : maxEvidenceScore >= 40 ? "text-amber-400" : "text-emerald-400"
                          }`}>
                            {maxEvidenceScore}
                          </span>
                          <span className="text-xs text-slate-500 font-bold">/ 100 max score</span>
                        </>
                      ) : (
                        <span className="text-sm font-bold text-slate-400">No provider returned a score</span>
                      )}
                      <span className="ml-auto">
                        <VerdictBadge verdict={worstVerdict || "Unknown"} />
                      </span>
                    </div>
                    <div className="mt-3 pt-2.5 border-t border-slate-800/80 space-y-1 text-[11px] text-slate-400">
                      <div className="flex items-center justify-between">
                        <span>IOCs with provider evidence:</span>
                        <span className="font-semibold text-slate-200">{evidenceIocs.length} / {iocs.length}</span>
                      </div>
                      <div className="flex items-center justify-between gap-2">
                        <span>Evidence from:</span>
                        <span className="font-semibold text-slate-200 text-right">
                          {providersWithEvidence.length ? providersWithEvidence.join(", ") : "none"}
                        </span>
                      </div>
                      {usedLabFixtures && (
                        <div className="text-fuchsia-300 flex items-center gap-1">
                          <FlaskConical className="h-3 w-3" />
                          Includes lab fixtures (simulation), not live lookups.
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>

              {/* Case metadata */}
              <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4 text-xs space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-400">Assigned Operator:</span>
                  <span className="font-semibold text-slate-200">{detail?.assigned_analyst || "Unassigned"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Resolved By:</span>
                  <span className="font-semibold text-purple-400">{detail?.resolved_by || "Not resolved"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Affected Asset:</span>
                  <span className="font-mono text-blue-300">{affectedAsset || "Not in payload"}</span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400">Matched Playbook:</span>
                  <span className="font-semibold text-slate-200 text-right truncate">
                    {playbook ? `${playbook.name} (${playbook.execution_mode})` : "None"}
                  </span>
                </div>
                {detail?.analyst_decision && (
                  <div className="pt-2 border-t border-slate-800 text-[11px] text-emerald-400 font-semibold flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5 flex-shrink-0" />
                    <span className="truncate">{detail.analyst_decision}</span>
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK */}
              <div>
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
                  MITRE ATT&CK
                </span>
                {mitreIds.length === 0 ? (
                  <p className="text-[11px] text-slate-500">
                    No ATT&CK mapping in the alert payload or the matched playbook.
                  </p>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {mitreIds.map((tid: string, idx: number) => {
                      const label = mitre?.technique?.[idx] || mitre?.tactic?.[idx];
                      return (
                        <span
                          key={`${tid}-${idx}`}
                          className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300 text-[11px] font-mono font-bold"
                        >
                          {tid}{label ? ` • ${label}` : ""}
                        </span>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Action center */}
            <div className="pt-3 border-t border-slate-800 space-y-2">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">
                Response Actions
              </span>

              {actionError && (
                <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-[11px] flex items-start gap-1.5">
                  <AlertCircle className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
                  <span>{actionError}</span>
                </div>
              )}
              {actionNotice && !actionError && (
                <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[11px]">
                  {actionNotice}
                </div>
              )}

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

              {vulnIntel?.hotl_autonomous_policy?.eligible_for_hotl && detail?.status !== "Contained" && (
                <button
                  onClick={handleExecuteNvdHotl}
                  disabled={actionLoading}
                  title="Runs the containment recommended for a critical CVE. Each action still goes through the connector and is labelled live or simulated."
                  className="w-full py-2 px-3 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold shadow-md shadow-rose-600/25 transition flex items-center justify-center space-x-1.5 disabled:opacity-50"
                >
                  <ShieldAlert className="h-3.5 w-3.5" />
                  <span>Run NVD-Recommended Containment</span>
                </button>
              )}

              <button
                onClick={handleBackgroundTipEnrich}
                disabled={actionLoading}
                className="w-full py-1.5 px-3 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 text-xs font-medium transition flex items-center justify-center space-x-1.5 disabled:opacity-50"
              >
                <RefreshCw className={`h-3 w-3 ${actionLoading ? "animate-spin text-blue-400" : ""}`} />
                <span>Re-run Threat Intel Enrichment</span>
              </button>
            </div>
          </div>

          {/* RIGHT MAIN VIEW — tabs */}
          <div className="lg:col-span-8 flex flex-col overflow-hidden bg-slate-900 min-h-0">
            <div className="px-5 pt-3 border-b border-slate-800 bg-slate-950/40 flex items-center space-x-2 flex-shrink-0 overflow-x-auto">
              {([
                { id: "context", label: "Triage & Context", icon: ClipboardList },
                { id: "intel", label: "Threat Intel", icon: Layers, badge: iocs.length ? String(iocs.length) : undefined },
                { id: "nvd", label: "NVD Vulnerabilities", icon: ShieldAlert, badge: vulnIntel?.cves_detected?.length ? String(vulnIntel.cves_detected.length) : undefined },
                { id: "response", label: "Playbook & Response", icon: Cpu, badge: actions.length ? String(actions.length) : undefined },
                { id: "timeline", label: "Timeline", icon: Clock },
              ] as Array<{ id: TabId; label: string; icon: React.ElementType; badge?: string }>).map((tab) => {
                const TabIcon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center space-x-2 px-3.5 py-2.5 rounded-t-lg text-xs font-bold border-b-2 transition whitespace-nowrap ${
                      isActive
                        ? "border-blue-500 text-blue-400 bg-slate-900"
                        : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
                    }`}
                  >
                    <TabIcon className="h-3.5 w-3.5" />
                    <span>{tab.label}</span>
                    {tab.badge && (
                      <span className="text-[10px] bg-blue-500/20 text-blue-300 px-1.5 py-0.2 rounded-full font-bold">
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            <div className="flex-1 p-5 overflow-y-auto space-y-4 min-h-0">
              {loading && !detail ? (
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
                  {/* TAB: TRIAGE & CONTEXT */}
                  {activeTab === "context" && (
                    <div className="space-y-4">
                      <div className="p-4 rounded-xl bg-gradient-to-r from-blue-950/40 via-indigo-950/30 to-slate-900 border border-blue-500/30">
                        <div className="flex items-center space-x-2 text-blue-400 text-xs font-bold uppercase tracking-wider mb-2">
                          <ClipboardList className="h-4 w-4" />
                          <span>Automated triage summary</span>
                        </div>
                        <p className="text-sm text-slate-200 leading-relaxed font-sans whitespace-pre-line">
                          {detail.triage_summary || "No triage summary was returned for this alert."}
                        </p>
                        <p className="text-[10px] text-slate-500 mt-2">
                          Rule-based summary generated from the alert, its IOC verdicts and recorded actions.
                        </p>
                      </div>

                      <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 space-y-2">
                        <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-1">
                          Rule Identification
                        </span>
                        <div className="text-xs text-slate-300">
                          <span className="font-semibold text-white">Rule ID:</span> {detail.rule_id}
                        </div>
                        <div className="text-xs text-slate-300">
                          <span className="font-semibold text-white">Description:</span>{" "}
                          {detail.raw_payload?.rule?.description || "No description in payload"}
                        </div>
                        {detail.raw_payload?.rule?.level !== undefined && (
                          <div className="text-xs text-slate-300">
                            <span className="font-semibold text-white">Rule level:</span> {String(detail.raw_payload.rule.level)}
                          </div>
                        )}
                      </div>

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

                  {/* TAB: THREAT INTEL */}
                  {activeTab === "intel" && (
                    <div className="space-y-4">
                      <p className="text-[11px] text-slate-400 leading-relaxed">
                        Each indicator is looked up with every configured provider. A score is only shown when a provider
                        returned evidence; &ldquo;Not found&rdquo; means the provider has no reputation data for it, and an
                        indicator with no evidence stays <b>Unknown</b>.
                      </p>

                      {iocs.length === 0 ? (
                        <div className="p-6 text-center text-xs text-slate-500 italic bg-slate-950 border border-slate-800 rounded-xl">
                          No IOCs were extracted from this alert&apos;s telemetry.
                        </div>
                      ) : (
                        iocs.map((ioc) => {
                          const providers = getProviders(ioc);
                          const evidence = iocHasEvidence(ioc);
                          const enrichment = ENRICHMENT_LABELS[ioc.enrichment_status || ""];
                          return (
                            <div key={ioc.artifact_id} className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                              <div className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 bg-slate-900/60">
                                <div className="space-y-1 min-w-0">
                                  <div className="flex items-center flex-wrap gap-2">
                                    <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                                      {ioc.artifact_type}
                                    </span>
                                    <VerdictBadge verdict={verdictOf(ioc)} />
                                    <span className={`text-[10px] font-semibold ${enrichment?.className || "text-slate-400"}`}>
                                      {enrichment?.label || (ioc.enrichment_status ? ioc.enrichment_status : "Enrichment status not recorded")}
                                    </span>
                                  </div>
                                  <div className="font-mono text-xs text-slate-200 select-all break-all">{ioc.value}</div>
                                </div>
                                <div className="sm:text-right flex-shrink-0">
                                  {evidence ? (
                                    <>
                                      <div className="text-xs font-bold font-mono text-white">{ioc.threat_score}/100</div>
                                      <div className="text-[10px] text-slate-500">max provider score</div>
                                    </>
                                  ) : (
                                    <div className="text-[11px] text-slate-500">No score (no provider evidence)</div>
                                  )}
                                </div>
                              </div>

                              {providers.length === 0 ? (
                                <div className="p-3 text-[11px] text-slate-500 italic">
                                  No per-provider results were stored for this indicator.
                                </div>
                              ) : (
                                <table className="w-full text-left text-[11px]">
                                  <thead className="text-slate-500 uppercase tracking-wider">
                                    <tr>
                                      <th className="py-2 px-3 font-bold">Provider</th>
                                      <th className="py-2 px-3 font-bold">Status</th>
                                      <th className="py-2 px-3 font-bold">Score</th>
                                      <th className="py-2 px-3 font-bold">Verdict</th>
                                      <th className="py-2 px-3 font-bold">Details</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-800/70">
                                    {providers.map(([key, p]) => {
                                      const meta = PROVIDER_STATUS[p.status] || {
                                        label: p.status,
                                        className: "bg-slate-800 text-slate-400 border-slate-700",
                                        hint: "",
                                      };
                                      const summaryEntries = p.summary && typeof p.summary === "object" ? Object.entries(p.summary) : [];
                                      return (
                                        <tr key={key} className="align-top">
                                          <td className="py-2 px-3 font-semibold text-slate-200 whitespace-nowrap">{providerLabel(key, p)}</td>
                                          <td className="py-2 px-3">
                                            <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold whitespace-nowrap ${meta.className}`} title={meta.hint}>
                                              {meta.label}
                                            </span>
                                          </td>
                                          <td className="py-2 px-3 font-mono text-slate-200 whitespace-nowrap">
                                            {providerHasScore(p) ? `${p.threat_score}/100` : <span className="text-slate-500">—</span>}
                                          </td>
                                          <td className="py-2 px-3 text-slate-300">{p.verdict || <span className="text-slate-500">—</span>}</td>
                                          <td className="py-2 px-3 text-slate-400">
                                            {p.error && <div className="text-rose-400">{p.error}</div>}
                                            {summaryEntries.length > 0 && (
                                              <div className="space-y-0.5">
                                                {summaryEntries.slice(0, 6).map(([k, v]) => (
                                                  <div key={k} className="break-all">
                                                    <span className="text-slate-500">{k}:</span> <span className="text-slate-300">{formatSummaryValue(v)}</span>
                                                  </div>
                                                ))}
                                              </div>
                                            )}
                                            {!p.error && summaryEntries.length === 0 && <span className="text-slate-600">—</span>}
                                            {p.queried_at && (
                                              <div className="text-[10px] text-slate-600 mt-0.5">{formatTime(p.queried_at)}</div>
                                            )}
                                          </td>
                                        </tr>
                                      );
                                    })}
                                  </tbody>
                                </table>
                              )}
                            </div>
                          );
                        })
                      )}
                    </div>
                  )}

                  {/* TAB: NVD */}
                  {activeTab === "nvd" && (
                    <div className="space-y-4">
                      {!vulnIntel ? (
                        <div className="p-6 text-center text-xs text-slate-500 italic">
                          NVD correlation is unavailable for this alert.
                        </div>
                      ) : (
                        <>
                          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between gap-4">
                            <div>
                              <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                                CVE identifiers in alert text
                              </span>
                              <div className="text-lg font-black text-white mt-0.5">
                                {vulnIntel.cves_detected?.length ? vulnIntel.cves_detected.join(", ") : "None found"}
                              </div>
                              {(vulnIntel.status || vulnIntel.message) && (
                                <div className="text-[11px] text-slate-400 mt-1">
                                  {[vulnIntel.status, vulnIntel.message].filter(Boolean).join(" — ")}
                                </div>
                              )}
                            </div>
                            <div className="text-right">
                              <span className="text-xs text-slate-400 block">Max CVSS</span>
                              <span className={`text-xl font-black ${
                                typeof vulnIntel.max_cvss_score === "number"
                                  ? vulnIntel.max_cvss_score >= 9.0 ? "text-rose-400" : vulnIntel.max_cvss_score >= 7.0 ? "text-orange-400" : "text-amber-400"
                                  : "text-slate-500"
                              }`}>
                                {typeof vulnIntel.max_cvss_score === "number" && vulnIntel.max_cvss_score > 0 ? vulnIntel.max_cvss_score : "N/A"}
                              </span>
                            </div>
                          </div>

                          {(vulnIntel.vulnerabilities ?? []).map((v) => (
                            <div key={v.cve_id} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                              <div className="flex items-center justify-between gap-3">
                                <span className="font-mono font-bold text-white text-sm">{v.cve_id}</span>
                                <div className="flex items-center gap-2 text-[11px]">
                                  {v.status && <span className="px-1.5 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-300">{v.status}</span>}
                                  <span className="font-mono text-slate-200">
                                    CVSS {typeof v.cvss_score === "number" ? v.cvss_score : "not available"}
                                    {v.severity ? ` · ${v.severity}` : ""}
                                  </span>
                                </div>
                              </div>
                              {v.description && <p className="text-xs text-slate-300 leading-relaxed">{v.description}</p>}
                              {v.hitl_remediation && v.hitl_remediation.length > 0 && (
                                <ul className="list-disc list-inside text-[11px] text-slate-400 space-y-0.5">
                                  {v.hitl_remediation.map((step, i) => <li key={i}>{step}</li>)}
                                </ul>
                              )}
                            </div>
                          ))}

                          {vulnIntel.hitl_remediation_steps && vulnIntel.hitl_remediation_steps.length > 0 && (
                            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                              <span className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                                <ShieldCheck className="h-4 w-4" />
                                Analyst remediation guidance (HITL)
                              </span>
                              <ul className="list-disc list-inside text-xs text-slate-200 space-y-1">
                                {vulnIntel.hitl_remediation_steps.map((step, i) => <li key={i}>{step}</li>)}
                              </ul>
                            </div>
                          )}

                          {vulnIntel.hotl_autonomous_policy && (
                            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                              <span className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                                <Zap className="h-4 w-4" />
                                Autonomous containment eligibility (HOTL)
                              </span>
                              <div className="text-xs text-slate-300">
                                {vulnIntel.hotl_autonomous_policy.eligible_for_hotl
                                  ? "Eligible: a critical CVSS rating was confirmed."
                                  : "Not eligible: analyst sign-off is required."}
                              </div>
                              {(vulnIntel.hotl_autonomous_policy.justification || vulnIntel.hotl_autonomous_policy.action_description) && (
                                <p className="text-xs text-slate-400 leading-relaxed">
                                  {vulnIntel.hotl_autonomous_policy.justification || vulnIntel.hotl_autonomous_policy.action_description}
                                </p>
                              )}
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  )}

                  {/* TAB: PLAYBOOK & RESPONSE */}
                  {activeTab === "response" && (
                    <div className="space-y-4">
                      {/* Matched playbook */}
                      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                        <div className="p-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                          <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                            <ScrollText className="h-3.5 w-3.5 text-blue-400" />
                            Matched Playbook
                          </span>
                          {playbook && (
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                              playbook.execution_mode === "HOTL"
                                ? "bg-blue-500/10 text-blue-400 border-blue-500/30"
                                : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                            }`}>
                              {playbook.execution_mode}
                            </span>
                          )}
                        </div>
                        {!playbook ? (
                          <div className="p-4 text-xs text-slate-500 italic">
                            No active playbook matched this alert.
                          </div>
                        ) : (
                          <div className="p-4 space-y-2">
                            <div className="text-sm font-bold text-white">{playbook.name}</div>
                            <div className="text-[11px] text-slate-400">
                              Target threat: <span className="text-slate-200">{playbook.target_threat}</span>
                              {playbookMitre && <> · MITRE <span className="font-mono text-purple-300">{playbookMitre}</span></>}
                              {!playbook.is_active && <span className="text-amber-400"> · disabled</span>}
                            </div>
                            {playbookSteps.length > 0 && (
                              <ol className="space-y-1 pt-1">
                                {playbookSteps.map((step, idx) => (
                                  <li key={idx} className="text-[11px] font-mono text-slate-300 flex items-center gap-2">
                                    <span className="text-slate-500 w-5 text-right">{String(step.order ?? step.step ?? idx + 1)}.</span>
                                    <span className="text-slate-100">{String(step.action ?? "?")}</span>
                                    {step.connector ? <span className="text-slate-500">({String(step.connector)})</span> : null}
                                  </li>
                                ))}
                              </ol>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Executions */}
                      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                        <div className="p-3 bg-slate-900 border-b border-slate-800">
                          <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                            <Cpu className="h-3.5 w-3.5 text-blue-400" />
                            Playbook Executions
                          </span>
                        </div>
                        {detail.playbook_executions.length === 0 ? (
                          <div className="p-4 text-xs text-slate-500 italic">No playbook executions recorded for this alert.</div>
                        ) : (
                          <div className="divide-y divide-slate-800">
                            {detail.playbook_executions.map((exec) => (
                              <div key={exec.execution_id} className="p-3.5 flex items-center justify-between hover:bg-slate-900/50">
                                <div className="space-y-1">
                                  <div className="text-xs font-bold text-white">{exec.playbook_name || "Ad-hoc response"}</div>
                                  <div className="text-[11px] text-slate-400 font-mono">Executed: {formatTime(exec.executed_at)}</div>
                                </div>
                                <div className="text-right">
                                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-200 border border-slate-700">
                                    {exec.status}
                                  </span>
                                  <div className="text-[11px] text-slate-300 font-mono mt-1" title="Measured from alert creation to completion">
                                    MTTR: {formatDuration(exec.mttr_seconds)}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Containment actions */}
                      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                        <div className="p-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                          <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                            <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                            Response Actions ({actions.length})
                          </span>
                          {simulatedActions > 0 && (
                            <span className="text-[10px] font-bold text-fuchsia-300 flex items-center gap-1">
                              <AlertTriangle className="h-3 w-3" />
                              {simulatedActions} simulated: no real system was changed
                            </span>
                          )}
                        </div>
                        {actions.length === 0 ? (
                          <div className="p-4 text-xs text-slate-500 italic">No response actions recorded for this alert yet.</div>
                        ) : (
                          <div className="divide-y divide-slate-800">{actions.map(renderActionRow)}</div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* TAB: TIMELINE */}
                  {activeTab === "timeline" && (
                    <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                      <div className="p-3 bg-slate-900 border-b border-slate-800">
                        <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                          <Clock className="h-3.5 w-3.5 text-indigo-400" />
                          Case Timeline
                        </span>
                      </div>
                      {timeline.length === 0 ? (
                        <div className="p-6 text-center text-xs text-slate-500 italic">No events recorded.</div>
                      ) : (
                        <ol className="p-4 space-y-3">
                          {timeline.map((ev, idx) => (
                            <li key={idx} className="flex gap-3">
                              <div className={`mt-1 h-2 w-2 rounded-full flex-shrink-0 ${
                                ev.kind === "action" ? "bg-emerald-400" : ev.kind === "ioc" ? "bg-blue-400" : ev.kind === "playbook" ? "bg-indigo-400" : ev.kind === "resolve" ? "bg-purple-400" : "bg-slate-400"
                              }`} />
                              <div className="min-w-0">
                                <div className="text-xs text-slate-200 font-semibold break-all">{ev.title}</div>
                                {ev.detail && <div className="text-[11px] text-slate-400">{ev.detail}</div>}
                                <div className="text-[10px] text-slate-500 font-mono">{formatTime(ev.at)}</div>
                              </div>
                            </li>
                          ))}
                        </ol>
                      )}
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
