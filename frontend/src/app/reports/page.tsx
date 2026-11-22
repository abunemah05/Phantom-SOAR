"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { 
  BarChart3, 
  Calendar, 
  Users, 
  Download, 
  ShieldCheck, 
  Clock, 
  Activity, 
  AlertTriangle, 
  CheckCircle2, 
  FileText,
  Filter,
  RefreshCw,
  Search,
  Lock
} from "lucide-react";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { AdminReportData } from "@/lib/types";
import { canAdminister } from "@/lib/roles";
import { useAuth } from "@/components/AuthGate";
import { AccessDenied, ErrorState, LoadingState, StaleBanner } from "@/components/StateViews";
import { formatDateTime, formatDuration, parseApiDate } from "@/lib/format";
import {
  DEFAULT_FILTERS,
  FILTER_STORAGE_KEY,
  MAX_RANGE_DAYS,
  RELATIVE_UNITS,
  ReportFilters,
  ReportPeriod,
  SEVERITIES,
  Severity,
  describeSeverities,
  formatUtcSeconds,
  maxRelativeValue,
  parseStoredState,
  serialiseStoredState,
  timeZoneLabel,
  toggleSeverity,
  isLastSelectedSeverity,
  validateFilters,
} from "@/lib/reportRange";

const SEVERITY_STYLES: Record<string, { badge: string; card: string }> = {
  Critical: { badge: "bg-rose-500/20 text-rose-400 border border-rose-500/30", card: "text-rose-400" },
  High: { badge: "bg-amber-500/20 text-amber-400 border border-amber-500/30", card: "text-amber-400" },
  Medium: { badge: "bg-blue-500/20 text-blue-400 border border-blue-500/30", card: "text-blue-400" },
  Low: { badge: "bg-slate-800 text-slate-400 border border-slate-700", card: "text-slate-300" },
  Other: { badge: "bg-slate-800 text-slate-400 border border-slate-700", card: "text-slate-500" },
};

const PERIOD_TABS: Array<{ id: ReportPeriod; label: string }> = [
  { id: "day", label: "Today (UTC)" },
  { id: "week", label: "Past 7 Days" },
  { id: "month", label: "Past 30 Days" },
  { id: "relative", label: "Last N..." },
  { id: "custom", label: "Custom Range" },
];

const INPUT_CLASS =
  "bg-slate-950 border border-slate-800 text-white text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500";

export default function AdminReportsPage() {
  const { user: currentUser } = useAuth();
  const isAuthorized = canAdminister(currentUser);
  
  // Filter state. `filters` are the controls as the operator left them; `applied` is the validated snapshot the
  // report was last requested with (the range inputs only take effect through "Apply"). Both survive a page
  // refresh (sessionStorage), so a reload shows the same report again.
  const [filters, setFilters] = useState<ReportFilters>(DEFAULT_FILTERS);
  const [applied, setApplied] = useState<ReportFilters>(DEFAULT_FILTERS);
  const [hydrated, setHydrated] = useState<boolean>(false);
  const [rangeError, setRangeError] = useState<string | null>(null);
  const [analysts, setAnalysts] = useState<Array<{ username: string; role: string }>>([]);
  const [zoneLabel, setZoneLabel] = useState<string>("");

  // Data & Loading States
  const [report, setReport] = useState<AdminReportData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<boolean>(false);

  const [analystsError, setAnalystsError] = useState<string | null>(null);
  const requestSeq = useRef(0);

  // Restore the previous selection once on the client (not during render: avoids a hydration mismatch).
  useEffect(() => {
    try {
      const stored = parseStoredState(window.sessionStorage.getItem(FILTER_STORAGE_KEY));
      setFilters(stored.filters);
      setApplied(stored.applied);
    } catch {
      /* storage unavailable (private mode): start from the defaults */
    }
    setZoneLabel(timeZoneLabel());
    setHydrated(true);
  }, []);

  useEffect(() => {
    if (!hydrated) return;
    try {
      window.sessionStorage.setItem(FILTER_STORAGE_KEY, serialiseStoredState({ filters, applied }));
    } catch {
      /* ignore */
    }
  }, [hydrated, filters, applied]);

  const loadAnalysts = useCallback(async () => {
    try {
      setAnalysts(await api.getAvailableAnalysts());
      setAnalystsError(null);
    } catch (err) {
      setAnalystsError(describeError(err, "Could not load the analyst list."));
    }
  }, []);

  const loadReport = useCallback(async () => {
    const check = validateFilters(applied);
    if (!check.ok) {
      setError(check.error);
      setLoading(false);
      return;
    }
    const seq = ++requestSeq.current;
    setLoading(true);
    setError(null);
    try {
      const data = await api.getAdminReport(check.params);
      if (seq === requestSeq.current) setReport(data);
    } catch (err) {
      if (seq === requestSeq.current) setError(describeError(err, "Failed to load the reporting analytics."));
    } finally {
      if (seq === requestSeq.current) setLoading(false);
    }
  }, [applied]);

  useEffect(() => {
    if (!isAuthorized || !hydrated) return;
    void loadAnalysts();
  }, [isAuthorized, hydrated, loadAnalysts]);

  useEffect(() => {
    if (!isAuthorized || !hydrated) return;
    void loadReport();
  }, [isAuthorized, hydrated, loadReport]);

  const handleDownloadPdf = async () => {
    const check = validateFilters(applied);
    if (!check.ok) {
      setError(check.error);
      return;
    }
    setDownloading(true);
    setError(null);
    try {
      await api.downloadAdminReportPdf(check.params);
    } catch (err) {
      setError(`PDF export failed: ${describeError(err)}`);
    } finally {
      setDownloading(false);
    }
  };

  const changeAnalyst = (analyst: string) => {
    setFilters((f) => ({ ...f, analyst }));
    setApplied((a) => ({ ...a, analyst }));
  };

  const changeSeverities = (severity: Severity | "all") => {
    const next = severity === "all" ? [] : toggleSeverity(filters.severities, severity);
    setFilters((f) => ({ ...f, severities: next }));
    setApplied((a) => ({ ...a, severities: next }));
  };

  const selectPeriod = (period: ReportPeriod) => {
    const next = { ...filters, period };
    setFilters(next);
    setRangeError(null);
    if (period === "custom" || period === "relative") {
      // Switch straight to the new range when its inputs are already valid; otherwise wait for the operator.
      if (validateFilters(next).ok) setApplied({ ...next });
    } else {
      setApplied((a) => ({ ...a, period }));
    }
  };

  const handleApplyRange = (e: React.FormEvent) => {
    e.preventDefault();
    const check = validateFilters(filters);
    if (!check.ok) {
      setRangeError(check.error);
      return;
    }
    setRangeError(null);
    setApplied({ ...filters });
  };

  const localStart = parseApiDate(report?.start_date);
  const localEnd = parseApiDate(report?.end_date);
  const localRange = localStart && localEnd ? `${formatDateTime(report?.start_date)} to ${formatDateTime(report?.end_date)}` : "";
  const relativeMax = maxRelativeValue(filters.relativeUnit);
  const reportSeverities = report?.filtered_severities ?? [];
  const severityCounts = report?.severity_breakdown ?? {};

  if (!isAuthorized) {
    return (
      <AccessDenied title="Access restricted (administrators only)">
        The reporting and audit engine is limited to administrators. Your role is <b>{currentUser?.role || "unknown"}</b>.
      </AccessDenied>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-2xl font-black text-white tracking-wide">SOC Analyst Audit & Performance Engine</h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
              Admin Restricted
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Audit cases handled by individual or team analysts, evaluate HITL decisions, and generate executive PDF reports.
          </p>
        </div>

        {/* Export PDF Button */}
        <div className="flex items-center space-x-3">
          <button
            onClick={handleDownloadPdf}
            disabled={downloading}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-lg shadow-blue-600/20 transition duration-150 disabled:opacity-50"
          >
            <Download className={`h-4 w-4 ${downloading ? "animate-pulse" : ""}`} />
            <span>{downloading ? "Preparing PDF..." : "Export Executive PDF Report"}</span>
          </button>
          <button
            onClick={() => void loadReport()}
            disabled={loading}
            className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 transition"
            title="Refresh Report Data"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-blue-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filter Toolbar (time range, analyst and severity) */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Quick Period Tabs */}
          <div className="flex flex-wrap items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800/80">
            {PERIOD_TABS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => selectPeriod(tab.id)}
                aria-pressed={filters.period === tab.id}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition ${
                  filters.period === tab.id
                    ? "bg-blue-600 text-white shadow-sm shadow-blue-600/30"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Analyst Selector Dropdown */}
          <div className="flex items-center space-x-2 min-w-[240px]">
            <Users className="h-4 w-4 text-slate-400" />
            <select
              aria-label="Analyst"
              value={filters.analyst}
              onChange={(e) => changeAnalyst(e.target.value)}
              className="flex-1 bg-slate-950 border border-slate-800 text-white text-xs font-medium rounded-lg px-3 py-2 focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="all">All SOC Analysts (Aggregate)</option>
              {analysts.map((a) => (
                <option key={a.username} value={a.username}>
                  {a.username} ({a.role})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Severity filter: "All" or any combination of levels */}
        <fieldset className="flex flex-wrap items-center gap-2 text-xs text-slate-300">
          <legend className="sr-only">Case severity</legend>
          <Filter className="h-4 w-4 text-slate-400" aria-hidden="true" />
          <span className="font-semibold text-slate-400 mr-1">Severity:</span>
          <label className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-md border cursor-pointer select-none transition ${
            filters.severities.length === 0 ? "bg-blue-600/20 border-blue-500/40 text-blue-300" : "border-slate-800 text-slate-400 hover:text-slate-200"
          }`}>
            <input
              type="checkbox"
              checked={filters.severities.length === 0}
              onChange={() => changeSeverities("all")}
              className="accent-blue-500"
            />
            <span className="font-semibold">All</span>
          </label>
          {SEVERITIES.map((sev) => {
            const checked = filters.severities.length === 0 || filters.severities.includes(sev);
            const last = isLastSelectedSeverity(filters.severities, sev);
            return (
              <label
                key={sev}
                title={last ? "At least one severity must stay selected. Tick All to show every severity." : undefined}
                className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-md border cursor-pointer select-none transition ${
                  filters.severities.includes(sev) ? SEVERITY_STYLES[sev].badge : "border-slate-800 text-slate-500 hover:text-slate-300"
                }`}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() => changeSeverities(sev)}
                  disabled={last}
                  className="accent-blue-500"
                />
                <span className="font-semibold">{sev}</span>
              </label>
            );
          })}
        </fieldset>

        {/* Relative range: last N units (visible when 'relative' is selected) */}
        {filters.period === "relative" && (
          <form onSubmit={handleApplyRange} className="pt-3 border-t border-slate-800/80 space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center space-x-2 text-xs text-slate-300">
                <Clock className="h-4 w-4 text-blue-400" />
                <label htmlFor="rel-value">Last</label>
                <input
                  id="rel-value"
                  type="number"
                  inputMode="numeric"
                  min={1}
                  max={relativeMax}
                  step={1}
                  required
                  value={filters.relativeValue}
                  onChange={(e) => setFilters((f) => ({ ...f, relativeValue: e.target.value }))}
                  className={`${INPUT_CLASS} w-28`}
                />
                <select
                  aria-label="Time unit"
                  value={filters.relativeUnit}
                  onChange={(e) => setFilters((f) => ({ ...f, relativeUnit: e.target.value as ReportFilters["relativeUnit"] }))}
                  className={INPUT_CLASS}
                >
                  {RELATIVE_UNITS.map((u) => (
                    <option key={u} value={u}>{u}</option>
                  ))}
                </select>
              </div>
              <button type="submit" className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition">
                Apply Filter
              </button>
            </div>
            <p className="text-[11px] text-slate-500">
              The range ends at the moment the report is generated (server clock). Up to {MAX_RANGE_DAYS} days.
            </p>
            {rangeError && <p role="alert" className="text-[11px] font-semibold text-rose-400">{rangeError}</p>}
          </form>
        )}

        {/* Custom date-time range (visible when 'custom' is active) */}
        {filters.period === "custom" && (
          <form onSubmit={handleApplyRange} className="pt-3 border-t border-slate-800/80 space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center space-x-2 text-xs text-slate-300">
                <Calendar className="h-4 w-4 text-blue-400" />
                <label htmlFor="custom-start">Start:</label>
                <input
                  id="custom-start"
                  type="datetime-local"
                  step={1}
                  required
                  value={filters.customStart}
                  onChange={(e) => setFilters((f) => ({ ...f, customStart: e.target.value }))}
                  className={INPUT_CLASS}
                />
              </div>

              <div className="flex items-center space-x-2 text-xs text-slate-300">
                <label htmlFor="custom-end">End:</label>
                <input
                  id="custom-end"
                  type="datetime-local"
                  step={1}
                  value={filters.customEnd}
                  onChange={(e) => setFilters((f) => ({ ...f, customEnd: e.target.value }))}
                  className={INPUT_CLASS}
                />
              </div>

              <button type="submit" className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition">
                Apply Filter
              </button>
            </div>
            <p className="text-[11px] text-slate-500">
              Enter times in your time zone{zoneLabel ? ` (${zoneLabel})` : ""}; they are sent as UTC and both ends are
              inclusive. Leave the end empty for &quot;until now&quot;. Up to {MAX_RANGE_DAYS} days.
            </p>
            {rangeError && <p role="alert" className="text-[11px] font-semibold text-rose-400">{rangeError}</p>}
          </form>
        )}
      </div>

      {analystsError && <StaleBanner message={analystsError} onRetry={() => void loadAnalysts()} />}
      {error && !report && <ErrorState title="The report could not be loaded" message={error} onRetry={() => void loadReport()} />}
      {error && report && <StaleBanner message={error} onRetry={() => void loadReport()} />}
      {loading && !report && !error && <LoadingState label="Building the report..." />}

      {report && (
      <>
      {/* What this report covers: the exact range the server used (UTC, to the second) and the filters applied */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl px-4 py-3 text-xs text-slate-300 space-y-1.5" data-testid="report-summary">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Calendar className="h-4 w-4 text-blue-400" aria-hidden="true" />
          <span className="font-semibold text-slate-400">Range ({report.timezone ?? "UTC"}, inclusive):</span>
          <span className="font-mono text-white">{formatUtcSeconds(report.start_date)}</span>
          <span className="text-slate-500">to</span>
          <span className="font-mono text-white">{formatUtcSeconds(report.end_date)}</span>
          {localRange && <span className="text-slate-500">| your time zone: {localRange}</span>}
        </div>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Filter className="h-4 w-4 text-purple-400" aria-hidden="true" />
          <span className="font-semibold text-slate-400">Severity:</span>
          {reportSeverities.length === 0 ? (
            <span className="font-semibold text-white">{describeSeverities(reportSeverities)}</span>
          ) : (
            reportSeverities.map((sev) => (
              <span key={sev} className={`px-2 py-0.5 rounded text-[10px] font-bold ${(SEVERITY_STYLES[sev] ?? SEVERITY_STYLES.Other).badge}`}>
                {sev}
              </span>
            ))
          )}
          <span className="text-slate-600">|</span>
          <span className="font-semibold text-slate-400">Analyst:</span>
          <span className="font-semibold text-white">{report.filtered_analyst || "All analysts"}</span>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-1">
            <span>Total Cases Reviewed</span>
            <FileText className="h-4 w-4 text-blue-400" />
          </div>
          <div className="text-2xl font-black text-white">
            {report?.total_cases_reviewed ?? 0}
          </div>
          <span className="text-[11px] text-slate-500 mt-1 block">In selected range and severity</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-1">
            <span>Live Containment Executions</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-400">
            {report?.containment_by_mode?.live ?? 0}
          </div>
          <span className="text-[11px] text-slate-500 mt-1 block">
            Confirmed by the connector. All records: {report?.total_containment_actions ?? 0}
            {report?.containment_by_mode
              ? ` (${Object.entries(report.containment_by_mode).filter(([m]) => m !== "live").map(([m, n]) => `${m} ${n}`).join(", ") || "none other"})`
              : ""}
          </span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-1">
            <span>Average MTTR</span>
            <Clock className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black text-amber-400">
            {formatDuration(report?.average_mttr_seconds)}
          </div>
          <span className="text-[11px] text-slate-500 mt-1 block">Mean Time to Remediate</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-1">
            <span>Filtered Analyst Target</span>
            <Users className="h-4 w-4 text-purple-400" />
          </div>
          <div className="text-base font-black text-white truncate mt-1">
            {report?.filtered_analyst ? report.filtered_analyst : "All SOC Operators"}
          </div>
          <span className="text-[11px] text-purple-400 font-semibold block mt-0.5">
            {report?.analyst_breakdown.length ?? 0} operators reporting
          </span>
        </div>
      </div>

      {/* Cases by severity (within the selected range and filters) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4" aria-label="Cases by severity">
        {Object.entries(severityCounts).map(([sev, count]) => (
          <div key={sev} className="p-3 rounded-xl bg-slate-900 border border-slate-800">
            <div className="text-slate-400 text-xs font-medium mb-1">{sev} cases</div>
            <div className={`text-xl font-black ${(SEVERITY_STYLES[sev] ?? SEVERITY_STYLES.Other).card}`}>{count}</div>
          </div>
        ))}
      </div>

      {/* Analyst Decision & Performance Matrix Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className="h-4 w-4 text-blue-400" />
            <h3 className="text-sm font-bold text-white">Analyst Performance & Decision Matrix (HITL Actions)</h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            {formatUtcSeconds(report?.start_date)} to {formatUtcSeconds(report?.end_date)} {report?.timezone ?? "UTC"}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-bold uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Operator</th>
                <th className="py-3 px-4">Role</th>
                <th className="py-3 px-4">Assigned</th>
                <th className="py-3 px-4">Resolved</th>
                <th className="py-3 px-4 text-rose-400">Escalated (Contained)</th>
                <th className="py-3 px-4 text-amber-400">Monitored</th>
                <th className="py-3 px-4 text-slate-400">Dismissed</th>
                <th className="py-3 px-4 text-emerald-400">Containments</th>
                <th className="py-3 px-4">Avg MTTR</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {report?.analyst_breakdown && report.analyst_breakdown.length > 0 ? (
                report.analyst_breakdown.map((a) => (
                  <tr key={a.analyst_username} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-bold text-white flex items-center space-x-2">
                      <div className="h-6 w-6 rounded-md bg-blue-600/20 text-blue-400 border border-blue-500/30 flex items-center justify-center font-mono text-[10px]">
                        {a.analyst_username.substring(0, 2).toUpperCase()}
                      </div>
                      <span>{a.analyst_username}</span>
                    </td>
                    <td className="py-3 px-4 text-slate-400">{a.role}</td>
                    <td className="py-3 px-4 text-slate-200">{a.cases_assigned}</td>
                    <td className="py-3 px-4 text-emerald-400 font-semibold">{a.cases_resolved}</td>
                    <td className="py-3 px-4 font-bold text-rose-400">{a.escalated_count}</td>
                    <td className="py-3 px-4 text-amber-400 font-semibold">{a.monitored_count}</td>
                    <td className="py-3 px-4 text-slate-400">{a.dismissed_count}</td>
                    <td className="py-3 px-4 text-emerald-400 font-bold">{a.containment_actions_taken}</td>
                    <td className="py-3 px-4 font-mono text-slate-300">{formatDuration(a.avg_mttr_seconds)}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={9} className="text-center py-6 text-slate-500">
                    No operator actions recorded during this time window.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Case Logs Audit Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <FileText className="h-4 w-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">Case Investigation Activity Log</h3>
          </div>
          <span className="text-xs text-slate-500">Showing up to 100 entries</span>
        </div>

        <div className="overflow-x-auto max-h-[380px]">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-bold uppercase tracking-wider sticky top-0">
              <tr>
                <th className="py-2.5 px-4">Alert</th>
                <th className="py-2.5 px-4">Event / Rule</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">Resolved By</th>
                <th className="py-2.5 px-4">Analyst Decision</th>
                <th className="py-2.5 px-4">Created At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {report?.cases && report.cases.length > 0 ? (
                report.cases.map((c) => (
                  <tr key={c.alert_id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 px-4 font-mono font-bold text-blue-400">#{c.alert_id}</td>
                    <td className="py-2.5 px-4 text-white max-w-xs truncate">{c.rule_id}</td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        c.severity === "Critical" ? "bg-rose-500/20 text-rose-400 border border-rose-500/30" :
                        c.severity === "High" ? "bg-amber-500/20 text-amber-400 border border-amber-500/30" :
                        c.severity === "Medium" ? "bg-blue-500/20 text-blue-400 border border-blue-500/30" :
                        "bg-slate-800 text-slate-400"
                      }`}>
                        {c.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">{c.status}</td>
                    <td className="py-2.5 px-4 font-semibold text-purple-400">
                      {c.resolved_by || "Not resolved"}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 max-w-xs truncate">
                      {c.analyst_decision || "—"}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[11px] text-slate-500">
                      {formatDateTime(c.created_at)}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="text-center py-6 text-slate-500">
                    No cases found matching the criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
      </>
      )}
    </div>
  );
}
