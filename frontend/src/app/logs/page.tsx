"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Bell, ChevronDown, ChevronRight, Clock, Cpu, Database, Filter, Key, Lock, Network, Pause, Play, Radio, RefreshCw, ScrollText,
  Search, ShieldCheck, Terminal, X,
} from "lucide-react";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { formatTimeAgo, formatTimeOfDay } from "@/lib/format";
import { SystemLog } from "@/lib/types";
import { usePolling } from "@/hooks/usePolling";
import { EmptyState, ErrorState, LoadingState, StaleBanner } from "@/components/StateViews";

const SOURCES: Array<{ id: string; label: string; icon?: React.ElementType }> = [
  { id: "ALL", label: "All sources" },
  { id: "EDR", label: "EDR (endpoint)", icon: Cpu },
  { id: "XDR", label: "XDR (extended)", icon: ShieldCheck },
  { id: "SIEM", label: "SIEM (Wazuh)", icon: Database },
  { id: "TIP", label: "TIP (threat intel)", icon: Radio },
  { id: "FIREWALL", label: "Firewall and edge", icon: Network },
  { id: "IAM", label: "IAM and identity", icon: Key },
  { id: "ITSM", label: "ITSM and webhooks", icon: Bell },
  { id: "AUTOMATION", label: "Automation playbooks", icon: ScrollText },
  { id: "AUTH", label: "Authentication", icon: Lock },
  { id: "AI", label: "AI agent", icon: Cpu },
  { id: "RBAC", label: "Accounts (RBAC)", icon: Key },
];

const TIME_PRESETS = [
  { label: "All time", seconds: 0 },
  { label: "Last 30s", seconds: 30 },
  { label: "Last 1m", seconds: 60 },
  { label: "Last 5m", seconds: 300 },
  { label: "Last 15m", seconds: 900 },
  { label: "Last 1h", seconds: 3600 },
];

const PAGE = 300;
/** Backend maximum for GET /logs (it has no offset, so "load more" widens the window). */
const MAX_LIMIT = 1000;

function sourceClass(source: string): string {
  switch (source.toUpperCase()) {
    case "EDR": return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
    case "XDR": return "bg-purple-500/10 text-purple-400 border-purple-500/30";
    case "SIEM": return "bg-indigo-500/10 text-indigo-400 border-indigo-500/30";
    case "TIP": return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
    case "FIREWALL": return "bg-amber-500/10 text-amber-400 border-amber-500/30";
    case "IAM": return "bg-rose-500/10 text-rose-400 border-rose-500/30";
    case "ITSM": return "bg-blue-500/10 text-blue-400 border-blue-500/30";
    case "AUTOMATION": return "bg-teal-500/10 text-teal-400 border-teal-500/30";
    case "AI": return "bg-cyan-500/10 text-cyan-300 border-cyan-500/30";
    default: return "bg-slate-700/20 text-slate-400 border-slate-700";
  }
}

function levelClass(level: string): string {
  switch (level.toUpperCase()) {
    case "CRITICAL": return "bg-rose-600/20 text-rose-400 border-rose-500/40 font-black";
    case "ERROR": return "bg-red-500/10 text-red-400 border-red-500/30 font-bold";
    case "ACTION": return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 font-bold";
    case "WARNING": return "bg-amber-500/10 text-amber-400 border-amber-500/30 font-semibold";
    default: return "bg-slate-800 text-slate-300 border-slate-700 font-medium";
  }
}

export default function LogsPage() {
  const [logs, setLogs] = useState<SystemLog[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [limit, setLimit] = useState(PAGE);

  const [source, setSource] = useState("ALL");
  const [seconds, setSeconds] = useState(0);
  const [customSeconds, setCustomSeconds] = useState("");
  const [level, setLevel] = useState("ALL");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");

  const [live, setLive] = useState(true);
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});
  const request = useRef(0);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);

  const customValid = /^\d+$/.test(customSeconds) && Number(customSeconds) > 0 && Number(customSeconds) <= 86400;
  const activeSeconds = customSeconds && customValid ? Number(customSeconds) : seconds;

  const load = useCallback(
    async (showSpinner: boolean) => {
      const id = ++request.current;
      if (showSpinner) setLoading(true);
      try {
        const data = await api.getLogs({
          source: source !== "ALL" ? source : undefined,
          seconds: activeSeconds > 0 ? activeSeconds : undefined,
          level: level !== "ALL" ? level : undefined,
          search: debouncedSearch || undefined,
          limit,
        });
        if (id !== request.current) return;
        setLogs(data);
        setError(null);
      } catch (err) {
        if (id !== request.current) return;
        setError(describeError(err, "Could not load the telemetry logs."));
      } finally {
        if (id === request.current) setLoading(false);
      }
    },
    [source, activeSeconds, level, debouncedSearch, limit]
  );

  useEffect(() => {
    void load(true);
  }, [load]);

  // Live refresh every 5 s; nothing runs while the tab is hidden.
  usePolling(() => void load(false), 5000, live);

  const filtersActive = source !== "ALL" || activeSeconds > 0 || level !== "ALL" || debouncedSearch !== "";
  const canLoadMore = logs !== null && logs.length >= limit && limit < MAX_LIMIT;
  const atCeiling = logs !== null && logs.length >= MAX_LIMIT;

  const resetFilters = () => {
    setSource("ALL");
    setSeconds(0);
    setCustomSeconds("");
    setLevel("ALL");
    setSearch("");
    setLimit(PAGE);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-blue-600/10 border border-blue-500/20 text-blue-400">
            <Terminal className="h-6 w-6" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Telemetry &amp; audit logs</h1>
            <p className="text-xs text-slate-400">
              Append-only record of alert ingestion, enrichment, response actions (live or simulated), AI proposals, playbooks and sign-ins. Entries cannot be edited or deleted from the console.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            aria-pressed={live}
            onClick={() => setLive((v) => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 ${
              live ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" : "bg-slate-800 text-slate-400 border-slate-700"
            }`}
          >
            {live ? <Play className="h-3.5 w-3.5" aria-hidden="true" /> : <Pause className="h-3.5 w-3.5" aria-hidden="true" />}
            <span>{live ? "Live (5s, pauses when the tab is hidden)" : "Live refresh paused"}</span>
          </button>
          <button
            type="button"
            onClick={() => void load(true)}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-xl text-xs font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-blue-400" : ""}`} aria-hidden="true" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
        <div className="space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400">
            <Filter className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" /> Source
          </div>
          <div role="group" aria-label="Source filter" className="flex flex-wrap gap-2">
            {SOURCES.map((src) => {
              const Icon = src.icon;
              const selected = source === src.id;
              return (
                <button
                  key={src.id}
                  type="button"
                  aria-pressed={selected}
                  onClick={() => { setSource(src.id); setLimit(PAGE); }}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${
                    selected ? "bg-blue-600 text-white border border-blue-500" : "bg-slate-950 text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 border border-slate-800"
                  }`}
                >
                  {Icon && <Icon className="h-3.5 w-3.5 opacity-80" aria-hidden="true" />}
                  <span>{src.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="pt-3 border-t border-slate-800/80 space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400">
            <Clock className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" /> Time window
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div role="group" aria-label="Time window presets" className="flex flex-wrap gap-2">
              {TIME_PRESETS.map((preset) => {
                const selected = seconds === preset.seconds && !customSeconds;
                return (
                  <button
                    key={preset.seconds}
                    type="button"
                    aria-pressed={selected}
                    onClick={() => { setSeconds(preset.seconds); setCustomSeconds(""); setLimit(PAGE); }}
                    className={`px-3 py-1.5 rounded-xl text-xs font-semibold border focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 ${
                      selected ? "bg-amber-500/20 text-amber-300 border-amber-500/40" : "bg-slate-950 text-slate-400 hover:text-slate-200 border-slate-800"
                    }`}
                  >
                    {preset.label}
                  </button>
                );
              })}
            </div>
            <div className="flex items-center gap-1.5 ml-auto">
              <label htmlFor="log-custom-seconds" className="text-[11px] text-slate-500">Custom (seconds)</label>
              <input
                id="log-custom-seconds"
                inputMode="numeric"
                value={customSeconds}
                onChange={(e) => setCustomSeconds(e.target.value.replace(/\D/g, ""))}
                aria-invalid={customSeconds !== "" && !customValid}
                placeholder="e.g. 45"
                className="w-24 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-amber-500 text-center font-mono"
              />
              {customSeconds && (
                <button type="button" onClick={() => setCustomSeconds("")} aria-label="Clear custom time window" className="p-1 text-slate-500 hover:text-slate-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 rounded">
                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              )}
            </div>
          </div>
          {customSeconds !== "" && !customValid && <p role="alert" className="text-[11px] text-rose-400">Enter a whole number of seconds between 1 and 86400.</p>}
        </div>

        <div className="pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="relative w-full sm:w-96">
            <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
            <label htmlFor="log-search" className="sr-only">Search logs</label>
            <input
              id="log-search"
              type="search"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setLimit(PAGE); }}
              placeholder="Search messages, targets, hashes, rule IDs..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div className="flex items-center gap-2 w-full sm:w-auto">
            <label htmlFor="log-level" className="text-xs text-slate-400 font-medium">Level</label>
            <select
              id="log-level"
              value={level}
              onChange={(e) => { setLevel(e.target.value); setLimit(PAGE); }}
              className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500 font-semibold"
            >
              <option value="ALL">All levels</option>
              {["CRITICAL", "ERROR", "ACTION", "WARNING", "INFO"].map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-mono text-slate-400 font-bold">telemetry_stream.log</span>
          <span className="text-xs font-mono text-slate-400" aria-live="polite">{logs ? `${logs.length} events` : ""}</span>
        </div>

        {error && !logs ? (
          <div className="p-4"><ErrorState title="Could not load the logs" message={error} onRetry={() => void load(true)} /></div>
        ) : loading && !logs ? (
          <LoadingState label="Loading security telemetry..." />
        ) : (
          <>
            {error && <div className="p-3"><StaleBanner message={error} onRetry={() => void load(true)} /></div>}
            {logs && logs.length === 0 ? (
              <EmptyState icon={Terminal} title={filtersActive ? "No logs match the selected filters" : "No log events yet"}>
                {filtersActive ? (
                  <button type="button" onClick={resetFilters} className="px-3 py-1.5 bg-blue-600/20 text-blue-300 border border-blue-500/30 rounded-lg text-xs font-semibold">Clear filters</button>
                ) : (
                  "Events appear here as alerts are ingested and actions run."
                )}
              </EmptyState>
            ) : (
              <ul className="divide-y divide-slate-800/60 font-mono text-xs">
                {(logs ?? []).map((log) => {
                  const isOpen = !!expanded[log.log_id];
                  const hasDetails = !!log.details && Object.keys(log.details).length > 0;
                  return (
                    <li key={log.log_id} className="p-4 hover:bg-slate-800/30 flex flex-col space-y-2">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-slate-500 text-[11px] whitespace-nowrap">{formatTimeOfDay(log.created_at)} ({formatTimeAgo(log.created_at)})</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sourceClass(log.source)}`}>{log.source}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] border ${levelClass(log.level)}`}>{log.level}</span>
                          {log.target && (
                            <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 text-[10px] border border-slate-700/80">
                              target: <strong className="text-blue-300">{log.target}</strong>
                            </span>
                          )}
                        </div>
                        {hasDetails && (
                          <button
                            type="button"
                            aria-expanded={isOpen}
                            onClick={() => setExpanded((prev) => ({ ...prev, [log.log_id]: !prev[log.log_id] }))}
                            className="text-[11px] text-slate-500 hover:text-slate-300 flex items-center gap-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
                          >
                            <span>{isOpen ? "Hide payload" : "View payload"}</span>
                            {isOpen ? <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" /> : <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />}
                          </button>
                        )}
                      </div>
                      <div className="text-slate-200 text-xs font-sans font-medium pl-1 leading-relaxed">{log.message}</div>
                      {isOpen && log.details && (
                        <div className="mt-2 p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] text-slate-300 overflow-x-auto">
                          <div className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-1.5">Raw telemetry JSON</div>
                          <pre className="text-emerald-400">{JSON.stringify(log.details, null, 2)}</pre>
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
            {(canLoadMore || atCeiling) && (
              <div className="flex items-center justify-between gap-3 p-3 border-t border-slate-800 text-xs text-slate-400">
                <span>{atCeiling ? `Showing the newest ${MAX_LIMIT} events. Narrow the time window or filters to see older ones.` : `Showing the newest ${logs?.length ?? 0} events.`}</span>
                {canLoadMore && (
                  <button type="button" onClick={() => setLimit((l) => Math.min(MAX_LIMIT, l + PAGE))} className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
                    Load more
                  </button>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
