"use client";

import React, { useMemo, useState } from "react";
import { Bot, CheckCircle2, FlaskConical, Loader2, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { formatDateTime } from "@/lib/format";
import { confidenceText, policyText } from "@/lib/status";
import { AgentProposal, ExecutionResult } from "@/lib/types";
import { useConfirm } from "@/components/ConfirmDialog";
import { useRuntimeStatus } from "@/components/RuntimeStatusProvider";
import { useToast } from "@/components/Toast";
import { ExecutionModeBadge, ProposalStatusBadge, VerdictBadge } from "@/components/StatusBadges";

function paramsText(params: unknown): string {
  if (!params || typeof params !== "object" || Object.keys(params as object).length === 0) return "";
  return JSON.stringify(params);
}

function ResultCell({ result }: { result: ExecutionResult | undefined }) {
  if (!result) return <span className="text-slate-500">not executed</span>;
  if (typeof result.skipped === "string") return <span className="text-slate-400">skipped: {result.skipped}</span>;
  return (
    <div className="space-y-0.5">
      <ExecutionModeBadge mode={result.execution_mode} />
      {result.status && <div className="text-[10px] text-slate-400">{result.status}</div>}
    </div>
  );
}

/** Summary of how many results were simulated, for honest toasts. */
function resultSummary(results: ExecutionResult[] | undefined): string {
  const list = (results || []).filter((r) => typeof r.skipped !== "string");
  if (list.length === 0) return "";
  const count = (mode: string) => list.filter((r) => (r.execution_mode || "").toLowerCase() === mode).length;
  const parts = [
    ["live", count("live")],
    ["simulated", count("simulated")],
    ["blocked", count("blocked")],
    ["failed", count("failed")],
    ["skipped", count("skipped")],
  ]
    .filter(([, n]) => (n as number) > 0)
    .map(([label, n]) => `${n} ${label}`);
  const simulatedOnly = count("simulated") === list.length;
  return `${parts.join(", ")}${simulatedOnly ? " (simulation: nothing real was changed)" : ""}`;
}

/**
 * Full view of one AI proposal: verdict, confidence, reasoning, every proposed action with its policy
 * evaluation and execution result, and (for a pending proposal) the analyst's approve / reject controls.
 * All model-written text is rendered as plain text.
 */
export default function ProposalPanel({
  proposal,
  canDecide,
  onUpdated,
}: {
  proposal: AgentProposal;
  canDecide: boolean;
  onUpdated: (updated: AgentProposal) => void;
}) {
  const confirm = useConfirm();
  const toast = useToast();
  const { status: runtime } = useRuntimeStatus();
  const pending = proposal.status === "pending_approval";

  const selectable = useMemo(
    () => proposal.proposed_actions.map((_, i) => proposal.policy_evaluation[i]?.allowed !== false),
    [proposal]
  );
  const [selected, setSelected] = useState<boolean[]>(() => selectable.slice());
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const chosen = proposal.proposed_actions
    .map((a, i) => ({ a, i }))
    .filter(({ i }) => selected[i] && selectable[i]);
  const simulation = runtime?.simulation_mode === true;

  const approve = async () => {
    if (chosen.length === 0) return;
    const ok = await confirm({
      title: `Approve ${chosen.length} action${chosen.length === 1 ? "" : "s"} from proposal #${proposal.proposal_id}?`,
      message: simulation
        ? "Simulation mode is on: approved actions are only rehearsed and recorded as SIMULATED. Nothing will change on any real system."
        : "Simulation mode is off: approved actions run against your real systems (EDR, firewall, identity provider, ticketing) wherever credentials are configured, as soon as you confirm.",
      items: [
        ...chosen.map(({ a }) => `${a.action}${a.target ? ` on ${a.target}` : ""}`),
        "Each action is checked by the policy engine again before it runs; protected assets are still refused.",
        "Your decision and notes are recorded in the audit log.",
      ],
      confirmLabel: simulation ? "Approve (simulated)" : "Approve and execute",
      tone: simulation ? "default" : "danger",
    });
    if (!ok) return;
    setBusy("approve");
    setError(null);
    try {
      const allSelected = chosen.length === proposal.proposed_actions.length;
      const res = await api.approveProposal(proposal.proposal_id, {
        ...(notes.trim() ? { notes: notes.trim() } : {}),
        ...(allSelected ? {} : { action_indexes: chosen.map(({ i }) => i) }),
      });
      if (res?.proposal) onUpdated(res.proposal);
      const summary = resultSummary(res?.results ?? res?.proposal?.execution_results);
      toast.success(`Proposal #${proposal.proposal_id} approved${summary ? `: ${summary}` : "."}`);
      setNotes("");
    } catch (err) {
      setError(describeError(err, "Approval failed."));
    } finally {
      setBusy(null);
    }
  };

  const reject = async () => {
    const ok = await confirm({
      title: `Reject proposal #${proposal.proposal_id}?`,
      message: "No proposed action will be executed. The proposal is closed as rejected and your decision is recorded in the audit log.",
      confirmLabel: "Reject proposal",
      tone: "warning",
    });
    if (!ok) return;
    setBusy("reject");
    setError(null);
    try {
      const updated = await api.rejectProposal(proposal.proposal_id, notes.trim() ? { notes: notes.trim() } : {});
      onUpdated(updated);
      toast.success(`Proposal #${proposal.proposal_id} rejected.`);
      setNotes("");
    } catch (err) {
      setError(describeError(err, "Rejection failed."));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Bot className="h-4 w-4 text-cyan-300" aria-hidden="true" />
        <span className="text-sm font-bold text-white break-all">{proposal.agent_name}</span>
        <VerdictBadge verdict={proposal.verdict} />
        <span className="text-[11px] font-mono text-slate-300">confidence {confidenceText(proposal.confidence)}</span>
        <ProposalStatusBadge status={proposal.status} />
      </div>

      {proposal.summary && (
        <section>
          <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-1">Summary</h3>
          <p className="text-sm text-slate-200 whitespace-pre-wrap break-words">{proposal.summary}</p>
        </section>
      )}
      {proposal.reasoning && (
        <section>
          <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-1">Reasoning</h3>
          <p className="text-xs text-slate-300 whitespace-pre-wrap break-words leading-relaxed">{proposal.reasoning}</p>
          <p className="text-[10px] text-slate-500 mt-1">
            Written by the model from untrusted alert data. Treat it as a suggestion, not evidence.
          </p>
        </section>
      )}

      <section>
        <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-1">
          Proposed actions ({proposal.proposed_actions.length})
        </h3>
        {proposal.proposed_actions.length === 0 ? (
          <p className="text-xs text-slate-500 italic">No action was proposed, so there is nothing to approve.</p>
        ) : (
          <div className="overflow-x-auto border border-slate-800 rounded-xl">
            <table className="w-full text-left text-[11px]">
              <thead className="bg-slate-950/60 text-slate-500 uppercase tracking-wider">
                <tr>
                  {pending && canDecide && <th scope="col" className="py-2 px-3 w-8"><span className="sr-only">Include</span></th>}
                  <th scope="col" className="py-2 px-3 font-bold">Action</th>
                  <th scope="col" className="py-2 px-3 font-bold">Target</th>
                  <th scope="col" className="py-2 px-3 font-bold">Policy evaluation</th>
                  <th scope="col" className="py-2 px-3 font-bold">Execution result</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {proposal.proposed_actions.map((a, i) => {
                  const policy = policyText(proposal.policy_evaluation[i]);
                  const params = paramsText(a.params);
                  return (
                    <tr key={i} className="align-top">
                      {pending && canDecide && (
                        <td className="py-2 px-3">
                          <input
                            type="checkbox"
                            checked={Boolean(selected[i]) && selectable[i]}
                            disabled={!selectable[i] || busy !== null}
                            onChange={(e) =>
                              setSelected((prev) => prev.map((v, idx) => (idx === i ? e.target.checked : v)))
                            }
                            aria-label={`Include ${a.action}${a.target ? ` on ${a.target}` : ""}`}
                            className="h-3.5 w-3.5 accent-blue-500"
                          />
                        </td>
                      )}
                      <td className="py-2 px-3">
                        <div className="font-mono text-slate-100">{a.action}</div>
                        {params && <div className="font-mono text-[10px] text-slate-500 break-all mt-0.5">{params}</div>}
                      </td>
                      <td className="py-2 px-3 font-mono text-slate-300 break-all">{a.target || "—"}</td>
                      <td className={`py-2 px-3 ${policy.className}`}>{policy.text}</td>
                      <td className="py-2 px-3">
                        <ResultCell result={proposal.execution_results[i]} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <p className="text-[10px] text-slate-500">
        Created {formatDateTime(proposal.created_at)}
        {proposal.decided_by && ` · decided by ${proposal.decided_by}${proposal.decided_at ? ` at ${formatDateTime(proposal.decided_at)}` : ""}`}
        {proposal.decision_notes && ` · notes: ${proposal.decision_notes}`}
      </p>

      {pending && !canDecide && (
        <p className="text-xs text-slate-400 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
          Your role can read proposals but cannot approve or reject them.
        </p>
      )}

      {pending && canDecide && (
        <section className="border-t border-slate-800 pt-4 space-y-3" aria-label="Analyst decision">
          {simulation && (
            <p className="flex items-start gap-2 text-[11px] text-fuchsia-300 bg-fuchsia-500/10 border border-fuchsia-500/30 rounded-lg p-2.5">
              <FlaskConical className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" aria-hidden="true" />
              Simulation mode is on: approving only rehearses the actions. Nothing real happens and the alert is not contained.
            </p>
          )}
          <div className="space-y-1">
            <label htmlFor={`notes-${proposal.proposal_id}`} className="text-xs font-semibold text-slate-300">
              Decision notes (optional)
            </label>
            <textarea
              id={`notes-${proposal.proposal_id}`}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={2}
              maxLength={1000}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          {error && (
            <p role="alert" className="text-xs text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-lg p-2.5">
              {error}
            </p>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={approve}
              disabled={busy !== null || chosen.length === 0}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
            >
              {busy === "approve" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
              Approve {chosen.length > 0 && chosen.length < proposal.proposed_actions.length ? `${chosen.length} selected` : "all allowed"}
            </button>
            <button
              type="button"
              onClick={reject}
              disabled={busy !== null}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-200 border border-rose-500/40 text-xs font-bold disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
            >
              {busy === "reject" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <XCircle className="h-3.5 w-3.5" />}
              Reject
            </button>
            {chosen.length === 0 && proposal.proposed_actions.length > 0 && (
              <span className="text-[11px] text-amber-300">No action is selectable (policy denied every action or none is ticked).</span>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
