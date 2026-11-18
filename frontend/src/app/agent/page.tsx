"use client";

import React, { useCallback, useState } from "react";
import Link from "next/link";
import { Bot, ChevronLeft, ChevronRight, FlaskConical, RefreshCw, UserCheck } from "lucide-react";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { canDecideProposals, canViewConfig } from "@/lib/roles";
import { PROPOSAL_STATUS_FILTERS, autonomyMeta, confidenceText } from "@/lib/status";
import { AgentProposal } from "@/lib/types";
import { useResource } from "@/hooks/useResource";
import { useAuth } from "@/components/AuthGate";
import Dialog from "@/components/Dialog";
import InvestigateModal from "@/components/InvestigateModal";
import ProposalPanel from "@/components/agent/ProposalPanel";
import { EmptyState, ErrorState, InlineNotice, LoadingState, StaleBanner } from "@/components/StateViews";
import { ProposalStatusBadge, VerdictBadge } from "@/components/StatusBadges";

const PAGE_SIZE = 25;

export default function AgentPage() {
  const { user } = useAuth();
  const canDecide = canDecideProposals(user);

  const [statusFilter, setStatusFilter] = useState<string>("");
  const [alertFilter, setAlertFilter] = useState<string>("");
  const [offset, setOffset] = useState<number>(0);
  const [selected, setSelected] = useState<AgentProposal | null>(null);
  const [caseId, setCaseId] = useState<number | null>(null);

  const alertId = /^\d+$/.test(alertFilter.trim()) ? Number(alertFilter.trim()) : undefined;

  const statusFetcher = useCallback(() => api.getAgentStatus(), []);
  const agent = useResource(statusFetcher, { pollMs: 30_000 });

  const listFetcher = useCallback(
    () => api.getProposals({ status: statusFilter || undefined, alert_id: alertId, limit: PAGE_SIZE, offset }),
    [statusFilter, alertId, offset]
  );
  const proposals = useResource(listFetcher, { pollMs: 15_000 });

  const status = agent.data;
  const list = proposals.data;
  const total = list?.total ?? 0;
  const items = list?.items ?? [];
  const autonomy = autonomyMeta(status?.autonomy);

  const refreshAll = () => {
    void agent.reload();
    void proposals.reload();
  };

  const onUpdated = (updated: AgentProposal) => {
    setSelected(updated);
    refreshAll();
  };

  const changeFilter = (apply: () => void) => {
    apply();
    setOffset(0);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2.5">
            <Bot className="h-6 w-6 text-cyan-300" aria-hidden="true" />
            AI Agent
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            Model-assisted triage proposals. Every proposed action is checked by the policy engine; nothing outside the alert&apos;s own
            entities can be targeted, and an analyst decides unless policy explicitly allows automatic execution.
          </p>
        </div>
        <button
          type="button"
          onClick={refreshAll}
          className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${proposals.loading || agent.loading ? "animate-spin" : ""}`} aria-hidden="true" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Status card */}
      {agent.error && !status ? (
        <ErrorState title="AI agent status unavailable" message={agent.error} onRetry={() => void agent.reload()} />
      ) : !status ? (
        <LoadingState label="Loading AI agent status..." />
      ) : (
        <>
          {agent.error && <StaleBanner message={agent.error} onRetry={() => void agent.reload()} />}

          {status.simulation_mode && (
            <InlineNotice tone="warning">
              <span className="flex items-start gap-2">
                <FlaskConical className="h-4 w-4 flex-shrink-0 mt-0.5 text-fuchsia-300" aria-hidden="true" />
                <span>
                  <b className="text-fuchsia-200">Simulation mode is on: nothing real happens.</b> Approved or automatic actions are only rehearsed
                  and recorded as SIMULATED; no system is changed and alerts are not contained.
                </span>
              </span>
            </InlineNotice>
          )}
          {status.autonomy === "recommend_only" && (
            <InlineNotice tone="info">
              <span className="flex items-start gap-2">
                <UserCheck className="h-4 w-4 flex-shrink-0 mt-0.5" aria-hidden="true" />
                <span>
                  <b>Recommend only: humans decide.</b> Every AI proposal waits for an analyst to approve it before any action runs.
                </span>
              </span>
            </InlineNotice>
          )}
          {!status.enabled && (
            <InlineNotice tone="warning">
              Built-in AI triage is switched off, so no alert data is sent to a model.{" "}
              {canViewConfig(user) ? (
                <Link href="/configuration" className="underline font-semibold">
                  Open Configuration (AI category)
                </Link>
              ) : (
                "An administrator can enable it in Configuration."
              )}
            </InlineNotice>
          )}
          {status.enabled && !status.configured && (
            <InlineNotice tone="warning">AI triage is enabled but no OpenRouter API key is configured, so triage requests will be refused.</InlineNotice>
          )}

          <section aria-label="AI agent status" className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatusTile label="Built-in AI triage" value={status.enabled ? (status.configured ? "Enabled" : "Enabled, no key") : "Disabled"} tone={status.enabled && status.configured ? "good" : "warn"}
              sub={status.configured ? `API key set${status.key_source ? ` (${status.key_source})` : ""}` : "No API key"} />
            <StatusTile label="Model" value={status.model || "not set"} mono sub={status.auto_triage ? "Auto-triage on" : "Manual triage only"} tone="neutral" />
            <StatusTile label="Autonomy" value={autonomy.label} sub={`min confidence ${confidenceText(status.min_confidence)}`} tone={status.autonomy === "recommend_only" ? "good" : "warn"} title={autonomy.description} />
            <StatusTile label="Awaiting decision" value={String(status.pending_proposals)} tone={status.pending_proposals > 0 ? "warn" : "neutral"} sub="pending proposals"
              action={status.pending_proposals > 0 ? { label: "Show", onClick: () => changeFilter(() => setStatusFilter("pending_approval")) } : undefined} />
          </section>
          <p className="text-[11px] text-slate-500">
            {typeof status.max_alerts_per_minute === "number" && <>Local limit: {status.max_alerts_per_minute} alerts per minute. </>}
            {status.send_raw_payload === true ? (
              <span className="text-amber-300">The raw alert payload is sent to the model.</span>
            ) : status.send_raw_payload === false ? (
              <>Only a redacted summary of an alert is sent to the model.</>
            ) : null}
          </p>
        </>
      )}

      {/* Filters */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-wrap items-end gap-4">
        <div>
          <label htmlFor="proposal-status" className="block text-[11px] font-bold uppercase text-slate-500 mb-1">Status</label>
          <select
            id="proposal-status"
            value={statusFilter}
            onChange={(e) => changeFilter(() => setStatusFilter(e.target.value))}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {PROPOSAL_STATUS_FILTERS.map((f) => (
              <option key={f.value} value={f.value}>{f.label}</option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="proposal-alert" className="block text-[11px] font-bold uppercase text-slate-500 mb-1">Alert #</label>
          <input
            id="proposal-alert"
            inputMode="numeric"
            value={alertFilter}
            onChange={(e) => changeFilter(() => setAlertFilter(e.target.value))}
            placeholder="any"
            aria-invalid={alertFilter.trim() !== "" && alertId === undefined}
            className="w-28 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        {(statusFilter || alertFilter) && (
          <button
            type="button"
            onClick={() => changeFilter(() => { setStatusFilter(""); setAlertFilter(""); })}
            className="px-3 py-2 text-xs text-slate-400 hover:text-white underline"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Proposals */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        {proposals.error && !list ? (
          <div className="p-4"><ErrorState title="Could not load proposals" message={proposals.error} onRetry={() => void proposals.reload()} /></div>
        ) : proposals.loading && !list ? (
          <LoadingState label="Loading proposals..." />
        ) : (
          <>
            {proposals.error && <div className="p-3"><StaleBanner message={proposals.error} onRetry={() => void proposals.reload()} /></div>}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <caption className="sr-only">AI proposals, newest first</caption>
                <thead className="bg-slate-950/70 text-slate-400 font-bold uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th scope="col" className="py-3 px-4">Proposal</th>
                    <th scope="col" className="py-3 px-4">Alert</th>
                    <th scope="col" className="py-3 px-4">Verdict</th>
                    <th scope="col" className="py-3 px-4">Confidence</th>
                    <th scope="col" className="py-3 px-4">Actions</th>
                    <th scope="col" className="py-3 px-4">Status</th>
                    <th scope="col" className="py-3 px-4">Created</th>
                    <th scope="col" className="py-3 px-4 text-right"><span className="sr-only">Open</span></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {items.length === 0 ? (
                    <tr>
                      <td colSpan={8}>
                        <EmptyState icon={Bot} title={statusFilter || alertFilter ? "No proposals match these filters" : "No AI proposals yet"}>
                          {statusFilter || alertFilter
                            ? "Clear the filters to see every proposal."
                            : "Open an alert and use \"Run AI triage\", or let an AI agent submit proposals through the agent API."}
                        </EmptyState>
                      </td>
                    </tr>
                  ) : (
                    items.map((p) => (
                      <tr key={p.proposal_id} className="hover:bg-slate-800/40 transition">
                        <td className="py-3 px-4 font-mono font-bold text-white">#{p.proposal_id}
                          <div className="text-[10px] font-sans font-normal text-slate-500 truncate max-w-[10rem]" title={p.agent_name}>{p.agent_name}</div>
                        </td>
                        <td className="py-3 px-4">
                          <button type="button" onClick={() => setCaseId(p.alert_id)} className="font-mono font-bold text-blue-400 hover:text-blue-300 underline-offset-2 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded">
                            #{p.alert_id}
                          </button>
                        </td>
                        <td className="py-3 px-4"><VerdictBadge verdict={p.verdict} /></td>
                        <td className="py-3 px-4 font-mono text-slate-300">{confidenceText(p.confidence)}</td>
                        <td className="py-3 px-4 text-slate-300">{p.proposed_actions.length}</td>
                        <td className="py-3 px-4"><ProposalStatusBadge status={p.status} /></td>
                        <td className="py-3 px-4 font-mono text-[11px] text-slate-400">{formatDateTime(p.created_at)}</td>
                        <td className="py-3 px-4 text-right">
                          <button
                            type="button"
                            onClick={() => setSelected(p)}
                            className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600 text-blue-300 hover:text-white border border-blue-500/30 rounded-lg text-xs font-semibold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
                          >
                            {p.status === "pending_approval" && canDecide ? "Review" : "Details"}
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            <nav aria-label="Proposal pages" className="flex items-center justify-between gap-3 p-3 border-t border-slate-800 text-xs text-slate-400">
              <span>
                {total === 0 ? "0 proposals" : `Showing ${offset + 1}-${Math.min(offset + items.length, total)} of ${total}`}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                  <ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" /> Previous
                </button>
                <button
                  type="button"
                  disabled={offset + PAGE_SIZE >= total}
                  onClick={() => setOffset(offset + PAGE_SIZE)}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                  Next <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            </nav>
          </>
        )}
      </div>

      <Dialog
        open={selected !== null}
        onClose={() => setSelected(null)}
        title={selected ? `AI proposal #${selected.proposal_id} for alert #${selected.alert_id}` : ""}
        size="xl"
        icon={<Bot className="h-5 w-5 text-cyan-300 mt-0.5" aria-hidden="true" />}
      >
        {selected && (
          <>
            <ProposalPanel key={`${selected.proposal_id}-${selected.status}`} proposal={selected} canDecide={canDecide} onUpdated={onUpdated} />
            <div>
              <button type="button" onClick={() => setCaseId(selected.alert_id)} className="text-xs text-blue-400 hover:text-blue-300 underline">
                Open alert #{selected.alert_id}
              </button>
            </div>
          </>
        )}
      </Dialog>

      <InvestigateModal alertId={caseId} isOpen={caseId !== null} onClose={() => setCaseId(null)} onAlertUpdated={refreshAll} />
    </div>
  );
}

function StatusTile({
  label, value, sub, tone, mono, title, action,
}: {
  label: string;
  value: string;
  sub?: string;
  tone: "good" | "warn" | "neutral";
  mono?: boolean;
  title?: string;
  action?: { label: string; onClick: () => void };
}) {
  const color = tone === "good" ? "text-emerald-400" : tone === "warn" ? "text-amber-400" : "text-slate-100";
  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4" title={title}>
      <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`mt-1 font-black ${mono ? "font-mono text-sm break-all" : "text-xl"} ${color}`}>{value}</div>
      {sub && <div className="text-[11px] text-slate-500 mt-1">{sub}</div>}
      {action && (
        <button type="button" onClick={action.onClick} className="mt-2 text-[11px] text-blue-400 hover:text-blue-300 underline">
          {action.label}
        </button>
      )}
    </div>
  );
}
