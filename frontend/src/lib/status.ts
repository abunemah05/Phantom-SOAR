// Labels, colours and honest wording for every status the console can show. Pure functions, unit tested.

import { PolicyEvaluation } from "./types";

export interface BadgeMeta {
  label: string;
  className: string;
  hint: string;
}

const SLATE = "bg-slate-800 text-slate-400 border-slate-700";

// --- Alerts -------------------------------------------------------------------

const ALERT_STATUS: Record<string, BadgeMeta> = {
  new: {
    label: "New",
    className: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    hint: "Ingested and waiting to be routed.",
  },
  processing: {
    label: "Processing",
    className: "bg-cyan-500/10 text-cyan-300 border-cyan-500/40",
    hint: "Enrichment or a playbook run is in progress. The status will change when it finishes.",
  },
  triaged: {
    label: "Triaged",
    className: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    hint: "Waiting for an analyst decision (human in the loop).",
  },
  contained: {
    label: "Contained",
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    hint: "Response actions were executed against real systems.",
  },
  simulated: {
    label: "Simulated — not contained",
    className: "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/40 border-dashed",
    hint: "Simulation mode: response actions were only rehearsed. Nothing was changed on any real system, so this alert is NOT contained.",
  },
  monitoring: {
    label: "Monitoring",
    className: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    hint: "Kept open under monitoring; no response action was executed.",
  },
  resolved: {
    label: "Resolved",
    className: "bg-slate-500/10 text-slate-400 border-slate-500/30",
    hint: "Handled and closed out.",
  },
  closed: {
    label: "Closed",
    className: "bg-slate-500/10 text-slate-400 border-slate-500/30",
    hint: "Dismissed or closed by an analyst.",
  },
};

export function alertStatusMeta(status?: string | null): BadgeMeta {
  const key = (status || "").toLowerCase();
  return (
    ALERT_STATUS[key] || {
      label: status || "Unknown",
      className: "bg-blue-500/10 text-blue-400 border-blue-500/30",
      hint: "Status reported by the backend.",
    }
  );
}

/** Statuses offered as quick filters on the alerts page (values are what the backend filters on). */
export const ALERT_STATUS_FILTERS: Array<{ value: string; label: string }> = [
  { value: "ALL", label: "All" },
  { value: "Unresolved", label: "Unresolved" },
  { value: "New", label: "New" },
  { value: "Processing", label: "Processing" },
  { value: "Triaged", label: "Triaged" },
  { value: "Contained", label: "Contained" },
  { value: "Simulated", label: "Simulated" },
  { value: "Monitoring", label: "Monitoring" },
  { value: "Resolved", label: "Resolved" },
  { value: "Closed", label: "Closed" },
];

export function severityBadgeClass(severity?: string | null): string {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return "bg-rose-500/10 text-rose-400 border-rose-500/30";
    case "high":
      return "bg-orange-500/10 text-orange-400 border-orange-500/30";
    case "medium":
      return "bg-amber-500/10 text-amber-400 border-amber-500/30";
    default:
      return "bg-blue-500/10 text-blue-400 border-blue-500/30";
  }
}

// --- Timing -------------------------------------------------------------------

/** "retry in 45s" / "retry in 3m". Empty string when the backend gave no hint. */
export function retryText(seconds?: number | null): string {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds <= 0) return "";
  const s = Math.ceil(seconds);
  if (s < 90) return `retry in ${s}s`;
  return `retry in ${Math.ceil(s / 60)}m`;
}

// --- Threat-intel providers ---------------------------------------------------

const PROVIDER_STATUS: Record<string, BadgeMeta> = {
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
    className: SLATE,
    hint: "No API key is configured for this provider.",
  },
  error: {
    label: "Error",
    className: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    hint: "The lookup failed (network, quota or authentication error).",
  },
  rate_limited: {
    label: "Rate limited",
    className: "bg-amber-500/10 text-amber-300 border-amber-500/40",
    hint: "The provider (or the local request budget) refused the lookup. This is not evidence either way: the indicator stays Unknown until it is re-enriched.",
  },
  lab_fixture: {
    label: "Lab fixture",
    className: "bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/30",
    hint: "Simulation mode: a fixed lab value for a documentation-range IP or demo IOC, not a real lookup.",
  },
  skipped: {
    label: "Skipped",
    className: SLATE,
    hint: "Not looked up (private/reserved address or unsupported indicator type).",
  },
};

export function providerStatusMeta(status?: string | null, retryAfterSeconds?: number | null): BadgeMeta {
  const meta = PROVIDER_STATUS[(status || "").toLowerCase()] || {
    label: status || "Unknown",
    className: SLATE,
    hint: "",
  };
  if ((status || "").toLowerCase() === "rate_limited") {
    const retry = retryText(retryAfterSeconds);
    return { ...meta, label: retry ? `Rate limited — ${retry}` : meta.label };
  }
  return meta;
}

const ENRICHMENT: Record<string, { label: string; className: string }> = {
  enriched: { label: "Enriched", className: "text-emerald-400" },
  partial: { label: "Partially enriched", className: "text-amber-400" },
  unavailable: { label: "Enrichment unavailable", className: "text-rose-400" },
  not_configured: { label: "No TIP provider configured", className: "text-slate-400" },
  pending: { label: "Enrichment pending", className: "text-blue-400" },
  rate_limited: { label: "Rate limited", className: "text-amber-300" },
};

export function enrichmentMeta(status?: string | null): { label: string; className: string } {
  return (
    ENRICHMENT[(status || "").toLowerCase()] || {
      label: status ? status : "Enrichment status not recorded",
      className: "text-slate-400",
    }
  );
}

// --- NVD ----------------------------------------------------------------------

/** One honest sentence for the overall NVD lookup state. */
export function nvdLookupMessage(status?: string | null, retryAfterSeconds?: number | null): string {
  const retry = retryText(retryAfterSeconds);
  switch ((status || "").toLowerCase()) {
    case "live":
      return "Live NVD lookup.";
    case "pending":
      return "Lookup queued: CVE data is being fetched in the background. Reopen or refresh this case in a moment.";
    case "partial":
      return `Partial: some CVEs could not be looked up yet${retry ? ` (${retry})` : ""}.`;
    case "no_cves":
      return "No CVE identifiers in the alert text.";
    case "unavailable":
      return "NVD is unreachable or the lookup failed; no CVSS data is available.";
    case "rate_limited":
      return `NVD rate limit reached — ${retry || "retry later"}. No CVSS data was obtained.`;
    case "not_configured":
      return "No NVD API key is set, so no lookup was made.";
    default:
      return status ? `NVD status: ${status}.` : "";
  }
}

export function nvdCveStatusMeta(status?: string | null, retryAfterSeconds?: number | null): BadgeMeta {
  const key = (status || "").toLowerCase();
  const retry = retryText(retryAfterSeconds);
  switch (key) {
    case "live":
      return { label: "Live", className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30", hint: "NVD returned the CVE record." };
    case "not_found":
      return { label: "Not in NVD", className: SLATE, hint: "NVD has no record of this CVE id." };
    case "pending":
      return { label: "Pending", className: "bg-blue-500/10 text-blue-300 border-blue-500/30", hint: "Not cached yet; a background lookup was queued." };
    case "rate_limited":
      return {
        label: retry ? `Rate limited — ${retry}` : "Rate limited",
        className: "bg-amber-500/10 text-amber-300 border-amber-500/40",
        hint: "NVD (or the local request budget) refused the lookup. No CVSS data was obtained.",
      };
    case "not_configured":
      return { label: "Not configured", className: SLATE, hint: "No NVD API key is set." };
    case "unavailable":
      return { label: "Unavailable", className: "bg-rose-500/10 text-rose-400 border-rose-500/30", hint: "The lookup failed." };
    default:
      return { label: status || "Unknown", className: SLATE, hint: "" };
  }
}

// --- Response actions ---------------------------------------------------------

const EXECUTION_MODE: Record<string, BadgeMeta> = {
  live: {
    label: "LIVE",
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    hint: "A real API call was made to the connector.",
  },
  simulated: {
    label: "SIMULATED",
    className: "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/40",
    hint: "Simulation mode was on: the action was not sent to any system and nothing was changed on a real system. Not containment.",
  },
  skipped: {
    label: "SKIPPED",
    className: "bg-slate-700/40 text-slate-300 border-slate-600/50",
    hint: "Simulation mode is off but this connector has no credentials: the action was not performed.",
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

export function executionModeMeta(mode?: string | null): BadgeMeta {
  const key = (mode || "").toLowerCase();
  return (
    EXECUTION_MODE[key] || {
      label: mode ? mode.toUpperCase() : "UNRECORDED",
      className: SLATE,
      hint: "Recorded before execution modes were tracked.",
    }
  );
}

// --- AI agent -----------------------------------------------------------------

const PROPOSAL_STATUS: Record<string, BadgeMeta> = {
  pending_approval: {
    label: "Awaiting analyst decision",
    className: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    hint: "Nothing has run. An analyst must approve or reject this proposal.",
  },
  auto_executed: {
    label: "Auto-executed by policy",
    className: "bg-blue-500/10 text-blue-300 border-blue-500/30",
    hint: "Policy allowed every action without approval. Check each result for live vs simulated.",
  },
  partially_executed: {
    label: "Partially executed",
    className: "bg-blue-500/10 text-blue-300 border-blue-500/30",
    hint: "Some actions ran, the rest were blocked or still wait for approval.",
  },
  approved: {
    label: "Approved by analyst",
    className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    hint: "An analyst approved the selected actions.",
  },
  rejected: {
    label: "Rejected by analyst",
    className: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    hint: "An analyst rejected this proposal; nothing was executed.",
  },
  blocked: {
    label: "Blocked by policy",
    className: "bg-rose-500/10 text-rose-400 border-rose-500/30",
    hint: "The policy engine refused every proposed action.",
  },
  no_action: {
    label: "No action proposed",
    className: SLATE,
    hint: "The model proposed nothing, or its answer could not be validated, so nothing can run.",
  },
};

export function proposalStatusMeta(status?: string | null): BadgeMeta {
  return (
    PROPOSAL_STATUS[(status || "").toLowerCase()] || {
      label: status ? status.replace(/_/g, " ") : "Unknown",
      className: SLATE,
      hint: "",
    }
  );
}

export const PROPOSAL_STATUS_FILTERS: Array<{ value: string; label: string }> = [
  { value: "", label: "All statuses" },
  { value: "pending_approval", label: "Awaiting decision" },
  { value: "auto_executed", label: "Auto-executed" },
  { value: "partially_executed", label: "Partially executed" },
  { value: "approved", label: "Approved" },
  { value: "rejected", label: "Rejected" },
  { value: "blocked", label: "Blocked" },
  { value: "no_action", label: "No action" },
];

export function verdictClass(verdict?: string | null): string {
  switch ((verdict || "").toLowerCase()) {
    case "malicious":
      return "bg-rose-500/20 text-rose-400 border-rose-500/30";
    case "suspicious":
      return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    case "clean":
    case "benign":
      return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
    default:
      return "bg-slate-700/40 text-slate-300 border-slate-600/50";
  }
}

export function capitalize(text?: string | null): string {
  if (!text) return "Unknown";
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function confidenceText(confidence?: number | null): string {
  if (typeof confidence !== "number" || !Number.isFinite(confidence)) return "—";
  return `${Math.round(confidence * 100)}%`;
}

const AUTONOMY: Record<string, { label: string; description: string }> = {
  recommend_only: {
    label: "Recommend only",
    description: "Humans decide: every AI proposal waits for an analyst to approve it.",
  },
  low_impact: {
    label: "Low impact",
    description: "Low-impact actions may run automatically when confidence meets the minimum; everything else waits for approval.",
  },
  policy: {
    label: "Policy",
    description: "Low- and medium-impact actions may run automatically when confidence meets the minimum; high-impact actions always wait for approval.",
  },
};

export function autonomyMeta(autonomy?: string | null): { label: string; description: string } {
  return (
    AUTONOMY[(autonomy || "").toLowerCase()] || {
      label: autonomy || "Unknown",
      description: "Autonomy level reported by the backend.",
    }
  );
}

/** One policy decision as a short, colour-coded sentence. */
export function policyText(decision: PolicyEvaluation | undefined): { text: string; className: string } {
  if (!decision) return { text: "—", className: "text-slate-500" };
  const reasons = Array.isArray(decision.reasons) ? decision.reasons.join("; ") : "";
  const suffix = reasons ? `: ${reasons}` : "";
  if (decision.allowed === false) return { text: `Denied${suffix}`, className: "text-rose-400" };
  if (decision.requires_approval) return { text: `Needs approval${suffix}`, className: "text-amber-400" };
  if (decision.allowed) return { text: `Allowed${suffix}`, className: "text-emerald-400" };
  return { text: reasons || "—", className: "text-slate-400" };
}
