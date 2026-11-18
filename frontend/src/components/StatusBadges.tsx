"use client";

import React from "react";
import { FlaskConical, Loader2 } from "lucide-react";
import {
  alertStatusMeta,
  executionModeMeta,
  proposalStatusMeta,
  severityBadgeClass,
  verdictClass,
  capitalize,
} from "@/lib/status";

export function SeverityBadge({ severity }: { severity?: string | null }) {
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${severityBadgeClass(severity)}`}>
      {severity || "Unknown"}
    </span>
  );
}

/** Alert status. Simulated and Processing are visually distinct and labelled honestly. */
export function AlertStatusBadge({ status }: { status?: string | null }) {
  const meta = alertStatusMeta(status);
  const key = (status || "").toLowerCase();
  return (
    <span
      title={meta.hint}
      className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full border ${meta.className}`}
    >
      {key === "simulated" && <FlaskConical className="h-3 w-3" aria-hidden="true" />}
      {key === "processing" && <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />}
      {meta.label}
    </span>
  );
}

export function ExecutionModeBadge({ mode }: { mode?: string | null }) {
  const meta = executionModeMeta(mode);
  return (
    <span title={meta.hint} className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${meta.className}`}>
      {meta.label}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict?: string | null }) {
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${verdictClass(verdict)}`}>
      {capitalize(verdict)}
    </span>
  );
}

export function ProposalStatusBadge({ status }: { status?: string | null }) {
  const meta = proposalStatusMeta(status);
  return (
    <span title={meta.hint} className={`text-[10px] font-bold px-2 py-0.5 rounded border ${meta.className}`}>
      {meta.label}
    </span>
  );
}
