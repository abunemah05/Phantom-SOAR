"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
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
  ScrollText,
  Bot,
  Loader2,
} from "lucide-react";
import {
  AgentProposal,
  AlertDetail,
  AlertEntities,
  ContainmentAction,
  IocArtifact,
  TipProviderResult,
  VulnerabilityIntel,
} from "@/lib/types";
import { api } from "@/lib/api";
import { ApiError, describeError, errorBlockers } from "@/lib/errors";
import { formatDateTime, formatDuration, parseApiDate } from "@/lib/format";
import { canRespond } from "@/lib/roles";
import { enrichmentMeta, nvdCveStatusMeta, nvdLookupMessage, providerStatusMeta, retryText } from "@/lib/status";
import { useModalBehavior } from "./Dialog";
import { useAuth } from "./AuthGate";
import { useConfirm } from "./ConfirmDialog";
import { useRuntimeStatus } from "./RuntimeStatusProvider";
import { useToast } from "./Toast";
import ProposalPanel from "./agent/ProposalPanel";
import { ErrorState, InlineNotice, LoadingState } from "./StateViews";
import { AlertStatusBadge, ExecutionModeBadge, SeverityBadge, VerdictBadge } from "./StatusBadges";

interface InvestigateModalProps {
  alertId: number | null;
  isOpen: boolean;
  onClose: () => void;
  onAlertUpdated?: () => void;
}

type TabId = "context" | "intel" | "nvd" | "response" | "agent" | "timeline";

// --- Presentation helpers --------------------------------------------------

const PROVIDER_LABELS: Record<string, string> = {
  virustotal: "VirusTotal",
  alienvault_otx: "AlienVault OTX",
  otx: "AlienVault OTX",
  abuseipdb: "AbuseIPDB",
  threatfox: "ThreatFox",
};

const VERDICT_RANK: Record<string, number> = { malicious: 3, suspicious: 2, clean: 1, unknown: 0 };

const ENTITY_LABELS: Array<[keyof AlertEntities, string]> = [
  ["hosts", "Hosts"],
  ["ips", "IPs"],
  ["users", "Users"],
  ["processes", "Processes"],
  ["files", "Files"],
  ["hashes", "Hashes"],
  ["domains", "Domains"],
  ["urls", "URLs"],
];

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

function formatSummaryValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.length ? value.map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join(", ") : "none";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatTime(iso?: string | null): string {
  if (!iso) return "—";
  return formatDateTime(iso, iso);
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
  const { user } = useAuth();
  const { status: runtime } = useRuntimeStatus();
  const toast = useToast();
  const confirm = useConfirm();
  const responder = canRespond(user);

  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [vulnIntel, setVulnIntel] = useState<VulnerabilityIntel | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [triaging, setTriaging] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [triageError, setTriageError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("context");
  const [copiedPayload, setCopiedPayload] = useState<boolean>(false);
  const [expandedActions, setExpandedActions] = useState<Record<number, boolean>>({});
  const containerRef = useRef<HTMLDivElement>(null);
  const loadedFor = useRef<number | null>(null);

  useModalBehavior(containerRef, isOpen && alertId !== null, onClose);

  /**
   * The alert detail already carries vulnerability_intel, so the NVD data is not fetched a second time on open.
   * A dedicated refresh (GET /vulnerabilities) runs only while NVD reports pending or partial results.
   */
  const fetchAlertDetail = useCallback(async (id: number, quiet = false) => {
    if (!quiet) setLoading(true);
    setError(null);
    try {
      const data = await api.getAlertDetail(id);
      if (loadedFor.current !== null && loadedFor.current !== id) return;
      setDetail(data);
      setVulnIntel(data.vulnerability_intel ?? null);
    } catch (err) {
      setError(describeError(err, "Failed to load alert details."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen && alertId) {
      loadedFor.current = alertId;
      setActiveTab("context");
      setActionError(null);
      setActionNotice(null);
      setTriageError(null);
      setExpandedActions({});
      void fetchAlertDetail(alertId);
    } else {
      loadedFor.current = null;
      setDetail(null);
      setVulnIntel(null);
      setError(null);
    }
  }, [isOpen, alertId, fetchAlertDetail]);

  // Follow up on a queued or partial NVD lookup (a few tries, then the analyst can reopen the case).
  const nvdState = (vulnIntel?.lookup_status || vulnIntel?.status || "").toLowerCase();
  const nvdPending = nvdState === "pending" || nvdState === "partial";
  useEffect(() => {
    if (!isOpen || !alertId || !nvdPending) return;
    let tries = 0;
    const id = alertId;
    const timer = setInterval(async () => {
      tries += 1;
      if (tries > 5 || document.visibilityState === "hidden") {
        if (tries > 5) clearInterval(timer);
        return;
      }
      try {
        const fresh = await api.getAlertVulnerabilities(id);
        if (loadedFor.current === id) setVulnIntel(fresh);
      } catch {
        // The detail view keeps showing the last NVD state; the next tick or a reopen retries.
      }
    }, 8000);
    return () => clearInterval(timer);
  }, [isOpen, alertId, nvdPending]);

  if (!isOpen || !alertId) return null;

  const runAction = async (label: string, fn: () => Promise<unknown>, successText?: string) => {
    if (!detail) return;
    setActionLoading(true);
    setActionError(null);
    setActionNotice(null);
    try {
      await fn();
      await fetchAlertDetail(detail.alert_id, true);
      if (successText) setActionNotice(successText);
      if (onAlertUpdated) onAlertUpdated();
    } catch (err) {
      const blockers = errorBlockers(err);
      setActionError(`${label} failed: ${describeError(err)}${blockers.length ? ` (${blockers.join("; ")})` : ""}`);
    } finally {
      setActionLoading(false);
    }
  };

  const simulationOn = (detail?.simulation_mode ?? runtime?.simulation_mode) === true;
  const consequence = simulationOn
    ? "Simulation mode is on: each action is only rehearsed and recorded as SIMULATED. Nothing real changes and the alert is not contained."
    : "Each action runs against the connector and may change real systems. Protected assets are refused by policy.";

  const handleApprove = async () => {
    if (!detail) return;
    const ok = await confirm({
      title: `Approve containment for alert #${detail.alert_id}?`,
      message: `You approve the containment actions chosen by the matched playbook${detail.playbook ? ` (${detail.playbook.name})` : ""}.`,
      items: [consequence, "The decision is recorded under your username."],
      confirmLabel: "Approve containment",
      tone: simulationOn ? "default" : "danger",
    });
    if (!ok) return;
    await runAction(
      "Approval",
      () => api.approveAlert(detail.alert_id),
      simulationOn ? "Approved. Actions were simulated: the alert is NOT contained." : "Containment approved. Check each action's execution mode in Response Actions."
    );
  };

  const handleDismiss = async () => {
    if (!detail) return;
    const ok = await confirm({
      title: `Dismiss alert #${detail.alert_id}?`,
      message: "No containment runs and the alert is closed as a dismissed (false positive / accepted) case.",
      items: ["The decision is recorded under your username."],
      confirmLabel: "Dismiss alert",
      tone: "warning",
    });
    if (!ok) return;
    await runAction("Dismissal", () => api.dismissAlert(detail.alert_id), "Alert dismissed.");
  };

  const handleLowTicketKeep = async () => {
    if (!detail) return;
    const ok = await confirm({
      title: `Keep alert #${detail.alert_id} under monitoring?`,
      message: "No containment runs. The alert stays open with status Monitoring.",
      confirmLabel: "Keep and monitor",
    });
    if (!ok) return;
    await runAction(
      "Keep & monitor",
      () => api.submitAlertDecision(detail.alert_id, "keep_and_monitor", "Analyst confirmed monitoring for low-risk activity."),
      "Alert kept under monitoring."
    );
  };

  const handleLowTicketTakeAction = async () => {
    if (!detail) return;
    const ok = await confirm({
      title: `Take action on alert #${detail.alert_id}?`,
      message: "You escalate this low-severity alert for containment.",
      items: [consequence, "The decision is recorded under your username."],
      confirmLabel: "Take action",
      tone: simulationOn ? "default" : "danger",
    });
    if (!ok) return;
    await runAction(
      "Take action",
      () => api.submitAlertDecision(detail.alert_id, "take_action", "Analyst escalated a low-severity alert for containment."),
      simulationOn ? "Requested. Actions were simulated: the alert is NOT contained." : "Containment requested. Check each action's execution mode in Response Actions."
    );
  };

  const handleExecuteNvdHotl = async () => {
    if (!detail) return;
    const action = vulnIntel?.hotl_autonomous_policy?.action_description || vulnIntel?.hotl_autonomous_policy?.action_type;
    const ok = await confirm({
      title: "Run NVD-recommended containment?",
      message: `Runs the containment recommended for the critical CVE${action ? `: ${action}` : ""}.`,
      items: [consequence, "Each action still passes the policy engine and is labelled live or simulated."],
      confirmLabel: "Run containment",
      tone: simulationOn ? "default" : "danger",
    });
    if (!ok) return;
    await runAction(
      "NVD-recommended containment",
      () => api.executeNvdHotl(detail.alert_id),
      simulationOn ? "Simulated only: the alert is NOT contained." : "NVD-recommended containment was executed."
    );
  };

  const handleBackgroundTipEnrich = async () => {
    if (!detail) return;
    setActionLoading(true);
    setActionError(null);
    try {
      await api.triggerBackgroundTipEnrichment(detail.alert_id);
      setActionNotice("Re-enrichment queued. Results refresh shortly.");
      const id = detail.alert_id;
      setTimeout(() => {
        if (loadedFor.current !== id) return;
        void fetchAlertDetail(id, true);
        if (onAlertUpdated) onAlertUpdated();
      }, 2000);
    } catch (err) {
      setActionError(`Re-enrichment failed: ${describeError(err)}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRunTriage = async () => {
    if (!detail) return;
    setTriaging(true);
    setTriageError(null);
    try {
      const proposal = await api.triageAlert(detail.alert_id);
      toast.success(`AI triage finished: verdict ${proposal.verdict}, status ${proposal.status.replace(/_/g, " ")}.`);
      await fetchAlertDetail(detail.alert_id, true);
      setActiveTab("agent");
      if (onAlertUpdated) onAlertUpdated();
    } catch (err) {
      // 409: AI disabled, no key, rate limited (Retry-After), alert still Processing or already being triaged.
      // 502: the model call failed (the message is already safe to show).
      const retry = err instanceof ApiError && err.status === 409 ? retryText(err.retryAfterSeconds) : "";
      const prefix = err instanceof ApiError && err.status === 502 ? "The AI model call failed: " : "";
      setTriageError(`${prefix}${describeError(err, "AI triage failed.")}${retry ? ` (${retry})` : ""}`);
      setActiveTab("agent");
    } finally {
      setTriaging(false);
    }
  };

  const handleDownloadReport = async () => {
    setActionError(null);
    try {
      await api.downloadAlertReport(alertId);
    } catch (err) {
      setActionError(`PDF report unavailable: ${describeError(err)}`);
    }
  };

  const copyPayload = async () => {
    if (!detail?.raw_payload) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(detail.raw_payload, null, 2));
      setCopiedPayload(true);
      setTimeout(() => setCopiedPayload(false), 2000);
    } catch {
      setActionError("Could not copy to the clipboard. Select the JSON and copy it manually.");
    }
  };

  const toggleAction = (id: number) =>
    setExpandedActions((prev) => ({ ...prev, [id]: !prev[id] }));

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

  const entities = detail?.entities ?? null;
  const entityGroups = entities
    ? ENTITY_LABELS.map(([key, label]) => [label, Array.isArray(entities[key]) ? entities[key] : []] as [string, string[]]).filter(([, v]) => v.length > 0)
    : [];
  const routing = detail?.routing ?? null;
  const proposals: AgentProposal[] = detail?.agent_proposals ?? [];

  const isLowTicket = detail?.severity?.toLowerCase() === "low";
  const affectedAsset = detail?.raw_payload?.agent?.name || detail?.raw_payload?.agent?.ip || null;

  const timeline: Array<{ at: string; title: string; detail?: string | null; kind: string }> = detail
    ? [
        { at: detail.created_at, title: `Alert ingested from ${detail.source}`, detail: `${detail.rule_id} · severity ${detail.severity}`, kind: "ingest" },
        ...iocs.map((ioc) => ({
          at: ioc.created_at,
          title: `IOC ${ioc.artifact_type} ${ioc.value}`,
          detail: `Verdict ${verdictOf(ioc)} · ${enrichmentMeta(ioc.enrichment_status).label}`,
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
        ...(detail.agent_proposals ?? []).map((p) => ({
          at: p.created_at,
          title: `AI agent ${p.agent_name}: verdict ${p.verdict}`,
          detail: `${p.proposed_actions.length} proposed action(s) · ${p.status.replace(/_/g, " ")}`,
          kind: "agent",
        })),
        ...(detail.resolved_at
          ? [{ at: detail.resolved_at, title: `Resolved by ${detail.resolved_by || "unknown"}`, detail: detail.analyst_decision, kind: "resolve" }]
          : []),
      ]
        .filter((e) => e.at)
        .sort((a, b) => (parseApiDate(a.at)?.getTime() ?? 0) - (parseApiDate(b.at)?.getTime() ?? 0))
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
        ref={containerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="investigate-title"
        tabIndex={-1}
        className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-7xl h-[88vh] max-h-[92vh] flex flex-col shadow-2xl shadow-black overflow-hidden relative"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Header Bar */}
        <div className="p-4 px-6 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center space-x-3 overflow-hidden">
            <div className="h-9 w-9 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
              <ShieldAlert className="h-5 w-5 text-blue-400" aria-hidden="true" />
            </div>
            <div className="overflow-hidden">
              <div className="flex items-center space-x-2">
                <h2 id="investigate-title" className="text-base font-bold text-white tracking-wide truncate">
                  Investigation Case #{alertId} {detail ? `— ${detail.rule_id}` : ""}
                </h2>
                {detail && (
                  <>
                    <SeverityBadge severity={detail.severity} />
                    <AlertStatusBadge status={detail.status} />
                    {detail.simulation_mode && (
                      <span
                        className="text-[10px] px-2 py-0.5 rounded-full border font-black bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/40 flex items-center gap-1"
                        title="Simulation mode is on: no response action is sent to any system, even where credentials are saved."
                      >
                        <FlaskConical className="h-3 w-3" />
                        SIMULATION MODE
                      </span>
                    )}
                  </>
                )}
              </div>
              <p className="text-[11px] text-slate-400 font-mono truncate">
                Ingested: {parseApiDate(detail?.created_at)?.toUTCString() ?? "—"} | Source: {detail?.source || "—"}
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
              type="button"
              onClick={onClose}
              aria-label="Close investigation"
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

              <div aria-live="polite">
                {actionError && (
                  <InlineNotice tone="error" onDismiss={() => setActionError(null)}>{actionError}</InlineNotice>
                )}
                {actionNotice && !actionError && (
                  <InlineNotice tone="success" onDismiss={() => setActionNotice(null)}>{actionNotice}</InlineNotice>
                )}
              </div>

              {detail && (detail.status || "").toLowerCase() === "simulated" && (
                <InlineNotice tone="warning">
                  <b>Simulated, not contained.</b> Response actions were only rehearsed; the threat has not been stopped on any real system.
                </InlineNotice>
              )}
              {detail && (detail.status || "").toLowerCase() === "processing" && (
                <InlineNotice tone="info">Still processing: ingest and playbook run are in flight. Decisions are available when it finishes.</InlineNotice>
              )}

              {!responder && (
                <p className="text-[11px] text-slate-500">
                  Your role ({user?.role || "unknown"}) is read-only here: containment decisions and AI triage need an analyst role or above.
                </p>
              )}

              {responder && isLowTicket && detail?.status !== "Contained" && detail?.status !== "Closed" && (
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => void handleLowTicketKeep()}
                    disabled={actionLoading}
                    className="py-2 px-2.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/40 text-xs font-bold transition flex items-center justify-center space-x-1 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
                  >
                    <Eye className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Keep &amp; Monitor</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => void handleLowTicketTakeAction()}
                    disabled={actionLoading}
                    className="py-2 px-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold shadow-md shadow-amber-600/25 transition flex items-center justify-center space-x-1 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-300"
                  >
                    <Zap className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Take Action</span>
                  </button>
                </div>
              )}

              {responder && !isLowTicket && detail?.status === "Triaged" && (
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => void handleDismiss()}
                    disabled={actionLoading}
                    className="py-2 px-2.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/40 text-xs font-bold transition flex items-center justify-center space-x-1 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
                  >
                    <XCircle className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Deny / Dismiss</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => void handleApprove()}
                    disabled={actionLoading}
                    className="py-2 px-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-md shadow-emerald-600/25 transition flex items-center justify-center space-x-1 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-300"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Approve Contain</span>
                  </button>
                </div>
              )}

              {responder && vulnIntel?.hotl_autonomous_policy?.eligible_for_hotl && detail?.status !== "Contained" && (
                <button
                  type="button"
                  onClick={() => void handleExecuteNvdHotl()}
                  disabled={actionLoading}
                  title="Runs the containment recommended for a critical CVE. Each action still goes through the connector and is labelled live or simulated."
                  className="w-full py-2 px-3 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold shadow-md shadow-rose-600/25 transition flex items-center justify-center space-x-1.5 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-300"
                >
                  <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Run NVD-Recommended Containment</span>
                </button>
              )}

              {responder && (
                <button
                  type="button"
                  onClick={() => void handleRunTriage()}
                  disabled={actionLoading || triaging || (detail?.status || "").toLowerCase() === "processing"}
                  title="Ask the built-in AI to review this alert. It only proposes: every action is checked by the policy engine."
                  className="w-full py-2 px-3 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-200 border border-cyan-500/40 text-xs font-bold transition flex items-center justify-center space-x-1.5 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
                >
                  {triaging ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <Bot className="h-3.5 w-3.5" aria-hidden="true" />}
                  <span>{triaging ? "AI is reviewing..." : "Run AI triage"}</span>
                </button>
              )}

              {responder && (
                <button
                  type="button"
                  onClick={() => void handleBackgroundTipEnrich()}
                  disabled={actionLoading}
                  className="w-full py-1.5 px-3 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 text-xs font-medium transition flex items-center justify-center space-x-1.5 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                  <RefreshCw className={`h-3 w-3 ${actionLoading ? "animate-spin text-blue-400" : ""}`} aria-hidden="true" />
                  <span>Re-run Threat Intel Enrichment</span>
                </button>
              )}
            </div>
          </div>

          {/* RIGHT MAIN VIEW — tabs */}
          <div className="lg:col-span-8 flex flex-col overflow-hidden bg-slate-900 min-h-0">
            <div role="tablist" aria-label="Case sections" className="px-5 pt-3 border-b border-slate-800 bg-slate-950/40 flex items-center space-x-2 flex-shrink-0 overflow-x-auto">
              {([
                { id: "context", label: "Triage & Context", icon: ClipboardList },
                { id: "intel", label: "Threat Intel", icon: Layers, badge: iocs.length ? String(iocs.length) : undefined },
                { id: "nvd", label: "NVD Vulnerabilities", icon: ShieldAlert, badge: vulnIntel?.cves_detected?.length ? String(vulnIntel.cves_detected.length) : undefined },
                { id: "response", label: "Playbook & Response", icon: Cpu, badge: actions.length ? String(actions.length) : undefined },
                { id: "agent", label: "AI Agent", icon: Bot, badge: proposals.length ? String(proposals.length) : undefined },
                { id: "timeline", label: "Timeline", icon: Clock },
              ] as Array<{ id: TabId; label: string; icon: React.ElementType; badge?: string }>).map((tab) => {
                const TabIcon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    role="tab"
                    id={`case-tab-${tab.id}`}
                    aria-selected={isActive}
                    aria-controls="case-tabpanel"
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center space-x-2 px-3.5 py-2.5 rounded-t-lg text-xs font-bold border-b-2 transition whitespace-nowrap focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${
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

            <div role="tabpanel" id="case-tabpanel" aria-labelledby={`case-tab-${activeTab}`} className="flex-1 p-5 overflow-y-auto space-y-4 min-h-0">
              {loading && !detail ? (
                <LoadingState label="Loading incident telemetry and intelligence..." />
              ) : error && !detail ? (
                <ErrorState title="The case could not be loaded" message={error} onRetry={() => void fetchAlertDetail(alertId)} />
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

                      {entityGroups.length > 0 && (
                        <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 space-y-2">
                          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                            Entities in this alert
                          </span>
                          <p className="text-[10px] text-slate-500">Automated actions (playbooks, AI agent) may only target these.</p>
                          {entityGroups.map(([label, items]) => (
                            <div key={label} className="flex flex-wrap items-center gap-1.5 text-[11px]">
                              <span className="text-slate-400 w-20 flex-shrink-0">{label}:</span>
                              {items.map((item) => (
                                <span key={item} className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 font-mono text-slate-200 break-all">
                                  {item}
                                </span>
                              ))}
                            </div>
                          ))}
                        </div>
                      )}

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
                            onClick={() => void copyPayload()}
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
                          const enrichment = enrichmentMeta(ioc.enrichment_status);
                          return (
                            <div key={ioc.artifact_id} className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
                              <div className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 bg-slate-900/60">
                                <div className="space-y-1 min-w-0">
                                  <div className="flex items-center flex-wrap gap-2">
                                    <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                                      {ioc.artifact_type}
                                    </span>
                                    <VerdictBadge verdict={verdictOf(ioc)} />
                                    <span className={`text-[10px] font-semibold ${enrichment.className}`}>{enrichment.label}</span>
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
                                      const meta = providerStatusMeta(p.status, p.retry_after_seconds);
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
                              {(vulnIntel.lookup_status || vulnIntel.status || vulnIntel.message) && (
                                <div className="text-[11px] text-slate-400 mt-1" role="status">
                                  {[
                                    nvdLookupMessage(vulnIntel.lookup_status || vulnIntel.status, vulnIntel.retry_after_seconds),
                                    vulnIntel.message || vulnIntel.error,
                                  ].filter(Boolean).join(" ")}
                                  {nvdPending && " Refreshing automatically."}
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
                                  {v.status && (() => {
                                    const m = nvdCveStatusMeta(v.status, v.retry_after_seconds);
                                    return <span title={m.hint} className={`px-1.5 py-0.5 rounded border font-semibold ${m.className}`}>{m.label}</span>;
                                  })()}
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

                      {/* Routing decision */}
                      {routing && (
                        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-white uppercase tracking-wider">Routing decision</span>
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                              String(routing.mode).toUpperCase() === "HOTL"
                                ? "bg-blue-500/10 text-blue-400 border-blue-500/30"
                                : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                            }`}>
                              {routing.mode}
                            </span>
                          </div>
                          {(routing.reasons ?? []).map((r, i) => (
                            <p key={i} className="text-xs text-slate-300">{r}</p>
                          ))}
                          <div className="text-[11px] text-slate-400">
                            <span className="font-semibold text-slate-300">Evidence:</span>{" "}
                            {routing.evidence && routing.evidence.length > 0 ? (
                              <ul className="list-disc list-inside mt-1 space-y-0.5">
                                {routing.evidence.map((ev, i) => <li key={i}>{ev}</li>)}
                              </ul>
                            ) : (
                              "none confirmed (no Malicious indicator backed by live or lab intelligence; sender-reported severity is not evidence)."
                            )}
                          </div>
                        </div>
                      )}

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

                  {/* TAB: AI AGENT */}
                  {activeTab === "agent" && (
                    <div className="space-y-4">
                      <p className="text-[11px] text-slate-400 leading-relaxed">
                        AI verdicts and response proposals for this alert (built-in triage or an external agent). Every proposed action is
                        checked by the policy engine; anything not allowed automatically waits for an analyst.
                      </p>
                      {simulationOn && (
                        <InlineNotice tone="warning">Simulation mode is on: approving or auto-executing proposals changes nothing real and does not contain the alert.</InlineNotice>
                      )}
                      {triageError && (
                        <InlineNotice tone="error" onDismiss={() => setTriageError(null)}>{triageError}</InlineNotice>
                      )}
                      {responder && (
                        <button
                          type="button"
                          onClick={() => void handleRunTriage()}
                          disabled={triaging || actionLoading || (detail.status || "").toLowerCase() === "processing"}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-200 border border-cyan-500/40 text-xs font-bold disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
                        >
                          {triaging ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <Bot className="h-3.5 w-3.5" aria-hidden="true" />}
                          <span>{triaging ? "AI is reviewing..." : "Run AI triage"}</span>
                        </button>
                      )}
                      {proposals.length === 0 ? (
                        <div className="p-6 text-center text-xs text-slate-500 italic bg-slate-950 border border-slate-800 rounded-xl">
                          No AI proposal exists for this alert yet.
                        </div>
                      ) : (
                        proposals.map((p) => (
                          <div key={`${p.proposal_id}-${p.status}`} className="bg-slate-950 border border-slate-800 rounded-xl p-4">
                            <ProposalPanel
                              proposal={p}
                              canDecide={responder}
                              onUpdated={() => {
                                void fetchAlertDetail(detail.alert_id, true);
                                if (onAlertUpdated) onAlertUpdated();
                              }}
                            />
                          </div>
                        ))
                      )}
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
                                ev.kind === "action" ? "bg-emerald-400" : ev.kind === "ioc" ? "bg-blue-400" : ev.kind === "playbook" ? "bg-indigo-400" : ev.kind === "resolve" ? "bg-purple-400" : ev.kind === "agent" ? "bg-cyan-400" : "bg-slate-400"
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
