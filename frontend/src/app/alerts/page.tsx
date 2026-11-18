"use client";

import React, { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { AlertTriangle, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { Alert } from "@/lib/types";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { formatDateTime } from "@/lib/format";
import { ALERT_STATUS_FILTERS } from "@/lib/status";
import { usePolling } from "@/hooks/usePolling";
import InvestigateModal from "@/components/InvestigateModal";
import { EmptyState, ErrorState, LoadingState, StaleBanner } from "@/components/StateViews";
import { AlertStatusBadge, SeverityBadge } from "@/components/StatusBadges";

const PAGE_SIZE = 50;
const SEVERITIES = ["ALL", "Critical", "High", "Medium", "Low"];

/** The dashboard links here with ?status=unresolved or ?status=review; both are filters the backend understands. */
function normaliseStatusParam(param: string | null): string {
  if (!param) return "ALL";
  const lower = param.toLowerCase();
  if (lower === "all") return "ALL";
  if (lower === "unresolved") return "Unresolved";
  if (lower === "review") return "review";
  return param.charAt(0).toUpperCase() + param.slice(1).toLowerCase();
}

function AlertsContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const paramStatus = searchParams.get("status");

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [status, setStatus] = useState(() => normaliseStatusParam(paramStatus));

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const request = useRef(0);

  useEffect(() => {
    setStatus(normaliseStatusParam(paramStatus));
  }, [paramStatus]);

  const query = useMemo(() => ({ status: status === "ALL" ? undefined : status, severity: severity === "ALL" ? undefined : severity }), [status, severity]);

  /** (Re)load the first page. Pages already appended with "Load more" are kept, de-duplicated by alert id. */
  const loadFirst = useCallback(
    async (showSpinner: boolean, keepRest: boolean) => {
      const id = ++request.current;
      if (showSpinner) setLoading(true);
      try {
        const page = await api.getAlerts({ ...query, skip: 0, limit: PAGE_SIZE });
        if (id !== request.current) return;
        setAlerts((previous) => {
          if (!keepRest) return page;
          const ids = new Set(page.map((a) => a.alert_id));
          const tail = previous.slice(PAGE_SIZE).filter((a) => !ids.has(a.alert_id));
          return [...page, ...tail];
        });
        if (!keepRest) setHasMore(page.length === PAGE_SIZE);
        setError(null);
      } catch (err) {
        if (id !== request.current) return;
        setError(describeError(err, "Could not load alerts."));
      } finally {
        if (id === request.current) setLoading(false);
      }
    },
    [query]
  );

  useEffect(() => {
    void loadFirst(true, false);
  }, [loadFirst]);

  usePolling(() => void loadFirst(false, true), 20_000, true);

  const loadMore = async () => {
    setLoadingMore(true);
    try {
      const page = await api.getAlerts({ ...query, skip: alerts.length, limit: PAGE_SIZE });
      setAlerts((previous) => {
        const ids = new Set(previous.map((a) => a.alert_id));
        return [...previous, ...page.filter((a) => !ids.has(a.alert_id))];
      });
      setHasMore(page.length === PAGE_SIZE);
      setError(null);
    } catch (err) {
      setError(describeError(err, "Could not load more alerts."));
    } finally {
      setLoadingMore(false);
    }
  };

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return alerts;
    return alerts.filter(
      (a) =>
        a.rule_id.toLowerCase().includes(q) ||
        String(a.alert_id).includes(q) ||
        a.source.toLowerCase().includes(q) ||
        JSON.stringify(a.raw_payload || {}).toLowerCase().includes(q)
    );
  }, [alerts, search]);

  const filtered = status !== "ALL" || severity !== "ALL" || search.trim() !== "";

  const changeStatus = (value: string) => {
    setStatus(value);
    router.replace(value === "ALL" ? "/alerts" : `/alerts?status=${encodeURIComponent(value)}`);
  };

  const clearFilters = () => {
    setSearch("");
    setSeverity("ALL");
    setStatus("ALL");
    router.replace("/alerts");
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-black text-white tracking-tight">Alerts &amp; incident investigation</h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-bold" aria-live="polite">
              {visible.length} {visible.length === 1 ? "case" : "cases"}{hasMore ? "+" : ""}
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Alert queue with threat-intel consensus, vulnerability guidance, AI proposals and HITL/HOTL containment.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadFirst(true, false)}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} aria-hidden="true" />
          <span>Refresh queue</span>
        </button>
      </div>

      {(status === "Unresolved" || status === "review") && (
        <div role="status" className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-semibold flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0" aria-hidden="true" />
            <span>
              <strong>Review gate:</strong>{" "}
              {status === "review" ? "alerts waiting for an analyst decision (New or Triaged)." : "cases that are not resolved or closed yet."}
            </span>
          </div>
          <button type="button" onClick={clearFilters} className="text-xs text-amber-400 hover:text-white underline font-bold ml-4 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 rounded">
            Show all alerts
          </button>
        </div>
      )}

      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-3 shadow-lg">
        <div className="relative max-w-md">
          <Search className="h-4 w-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" aria-hidden="true" />
          <label htmlFor="alert-search" className="sr-only">Search loaded alerts</label>
          <input
            id="alert-search"
            type="search"
            placeholder="Search loaded alerts by ID, rule, source or payload..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <FilterRow label="Severity" options={SEVERITIES.map((s) => ({ value: s, label: s === "ALL" ? "All" : s }))} value={severity} onChange={setSeverity} accent="bg-blue-600" />
        <FilterRow
          label="Status"
          options={status === "review" ? [...ALERT_STATUS_FILTERS, { value: "review", label: "Needs review" }] : ALERT_STATUS_FILTERS}
          value={status}
          onChange={changeStatus}
          accent="bg-indigo-600"
        />
      </div>

      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        {error && alerts.length === 0 ? (
          <div className="p-4"><ErrorState title="Could not load the alert queue" message={error} onRetry={() => void loadFirst(true, false)} /></div>
        ) : loading && alerts.length === 0 ? (
          <LoadingState label="Loading alerts..." />
        ) : (
          <>
            {error && <div className="p-3"><StaleBanner message={error} onRetry={() => void loadFirst(true, false)} /></div>}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <caption className="sr-only">Alert queue, newest first</caption>
                <thead className="bg-slate-950/70 text-slate-400 font-bold uppercase tracking-wider border-b border-slate-800">
                  <tr>
                    <th scope="col" className="py-3.5 px-4">Case</th>
                    <th scope="col" className="py-3.5 px-4">Rule and detection</th>
                    <th scope="col" className="py-3.5 px-4">Severity</th>
                    <th scope="col" className="py-3.5 px-4">Status</th>
                    <th scope="col" className="py-3.5 px-4">IoCs and intel</th>
                    <th scope="col" className="py-3.5 px-4">Ingested</th>
                    <th scope="col" className="py-3.5 px-4 text-right"><span className="sr-only">Open</span></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {visible.length === 0 ? (
                    <tr>
                      <td colSpan={7}>
                        <EmptyState icon={ShieldAlert} title={filtered ? "No cases match the active filters" : "No security cases in the queue"}>
                          {filtered ? (
                            <button type="button" onClick={clearFilters} className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 rounded-lg text-xs font-semibold">
                              Clear filters
                            </button>
                          ) : (
                            "Alerts arrive through the authenticated SIEM / EDR / XDR webhooks."
                          )}
                        </EmptyState>
                      </td>
                    </tr>
                  ) : (
                    visible.map((alert) => (
                      <tr key={alert.alert_id} onClick={() => setSelectedId(alert.alert_id)} className="hover:bg-slate-800/50 cursor-pointer transition">
                        <td className="py-4 px-4 font-mono font-bold text-blue-400">#{alert.alert_id}</td>
                        <td className="py-4 px-4 max-w-md">
                          <div className="font-bold text-white tracking-wide truncate">{alert.rule_id}</div>
                          <div className="text-[11px] text-slate-400 truncate mt-0.5">
                            {alert.raw_payload?.rule?.description || alert.raw_payload?.full_log || alert.source}
                          </div>
                        </td>
                        <td className="py-4 px-4"><SeverityBadge severity={alert.severity} /></td>
                        <td className="py-4 px-4"><AlertStatusBadge status={alert.status} /></td>
                        <td className="py-4 px-4">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-slate-300">{alert.ioc_count || 0} artifacts</span>
                            {(alert.max_threat_score || 0) > 0 && (
                              <span className="text-[10px] px-1.5 rounded bg-rose-500/10 text-rose-400 font-mono font-bold">
                                max score {alert.max_threat_score}/100
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-4 px-4 text-slate-400 font-mono text-[11px]">{formatDateTime(alert.created_at)}</td>
                        <td className="py-4 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                          <button
                            type="button"
                            onClick={() => setSelectedId(alert.alert_id)}
                            aria-label={`Investigate alert ${alert.alert_id}`}
                            className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-300"
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
            <div className="flex items-center justify-between gap-3 p-3 border-t border-slate-800 text-xs text-slate-400">
              <span>{alerts.length} loaded{search.trim() ? `, ${visible.length} match the search` : ""}</span>
              {hasMore ? (
                <button type="button" onClick={() => void loadMore()} disabled={loadingMore} className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
                  {loadingMore ? "Loading..." : "Load more"}
                </button>
              ) : (
                alerts.length > 0 && <span>End of the list</span>
              )}
            </div>
          </>
        )}
      </div>

      <InvestigateModal
        alertId={selectedId}
        isOpen={selectedId !== null}
        onClose={() => setSelectedId(null)}
        onAlertUpdated={() => void loadFirst(false, true)}
      />
    </div>
  );
}

function FilterRow({
  label, options, value, onChange, accent,
}: {
  label: string;
  options: Array<{ value: string; label: string }>;
  value: string;
  onChange: (value: string) => void;
  accent: string;
}) {
  return (
    <div role="group" aria-label={`${label} filter`} className="flex flex-wrap items-center gap-1.5 text-xs">
      <span className="text-slate-500 text-[11px] font-bold uppercase mr-1">{label}:</span>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
          className={`px-2.5 py-1 rounded-md text-[11px] font-bold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${
            value === o.value ? `${accent} text-white` : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export default function AlertsPage() {
  return (
    <Suspense fallback={<LoadingState label="Loading investigation workspace..." />}>
      <AlertsContent />
    </Suspense>
  );
}
