"use client";

import React, { useState, useEffect, useRef } from "react";
import { 
  Terminal, 
  RefreshCw, 
  Clock, 
  Filter, 
  Search, 
  Trash2, 
  Zap, 
  CheckCircle2, 
  AlertCircle, 
  ShieldAlert, 
  Radio, 
  Play, 
  Pause, 
  ChevronDown, 
  ChevronRight, 
  Cpu, 
  ShieldCheck, 
  Database, 
  Network, 
  Key, 
  Bell, 
  ScrollText, 
  SlidersHorizontal,
  X
} from "lucide-react";
import { api } from "@/lib/api";
import { SystemLog } from "@/lib/types";

const SOURCES = [
  { id: "ALL", label: "All Sources" },
  { id: "EDR", label: "EDR (Endpoint)", icon: Cpu },
  { id: "XDR", label: "XDR (Extended)", icon: ShieldCheck },
  { id: "SIEM", label: "SIEM (Wazuh)", icon: Database },
  { id: "TIP", label: "TIP (Threat Intel)", icon: Radio },
  { id: "FIREWALL", label: "Firewall & Edge", icon: Network },
  { id: "IAM", label: "IAM & Identity", icon: Key },
  { id: "ITSM", label: "ITSM & Webhooks", icon: Bell },
  { id: "AUTOMATION", label: "Automation Playbooks", icon: ScrollText },
];

const TIME_PRESETS = [
  { label: "All Time", seconds: 0 },
  { label: "Last 30s", seconds: 30 },
  { label: "Last 60s (1m)", seconds: 60 },
  { label: "Last 300s (5m)", seconds: 300 },
  { label: "Last 900s (15m)", seconds: 900 },
  { label: "Last 3600s (1h)", seconds: 3600 },
];

export default function LogsPage() {
  const [logs, setLogs] = useState<SystemLog[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedSource, setSelectedSource] = useState<string>("ALL");
  const [selectedSeconds, setSelectedSeconds] = useState<number>(0);
  const [customSecondsInput, setCustomSecondsInput] = useState<string>("");
  const [selectedLevel, setSelectedLevel] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Live Auto-Refresh
  const [isLiveStreaming, setIsLiveStreaming] = useState<boolean>(true);
  const [expandedLogIds, setExpandedLogIds] = useState<Record<number, boolean>>({});
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const fetchLogs = async (showLoading: boolean = false) => {
    if (showLoading) setLoading(true);
    try {
      const activeSeconds = customSecondsInput && parseInt(customSecondsInput) > 0 
        ? parseInt(customSecondsInput) 
        : selectedSeconds > 0 ? selectedSeconds : undefined;

      const data = await api.getLogs({
        source: selectedSource !== "ALL" ? selectedSource : undefined,
        seconds: activeSeconds,
        level: selectedLevel !== "ALL" ? selectedLevel : undefined,
        search: searchQuery.trim() || undefined,
        limit: 300,
      });
      setLogs(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || "Failed to fetch telemetry logs.");
    } finally {
      if (showLoading) setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs(true);
  }, [selectedSource, selectedSeconds, selectedLevel, searchQuery]);

  // Live Stream Polling (every 3 seconds if active)
  useEffect(() => {
    if (!isLiveStreaming) return;
    const interval = setInterval(() => {
      fetchLogs(false);
    }, 3000);
    return () => clearInterval(interval);
  }, [isLiveStreaming, selectedSource, selectedSeconds, selectedLevel, searchQuery, customSecondsInput]);

  const handleApplyCustomSeconds = (e: React.FormEvent) => {
    e.preventDefault();
    const parsed = parseInt(customSecondsInput);
    if (!isNaN(parsed) && parsed > 0) {
      setSelectedSeconds(parsed);
      fetchLogs(true);
    }
  };

  const handleSeedFreshLogs = async () => {
    try {
      await api.seedLogs();
      setActionNotice("Injected fresh real-time security events into telemetry stream.");
      fetchLogs(true);
      setTimeout(() => setActionNotice(null), 3500);
    } catch (err: any) {
      setError("Failed to seed fresh logs.");
    }
  };

  const handleClearLogs = async () => {
    if (!confirm("Are you sure you want to purge all telemetry logs from the database?")) return;
    try {
      await api.clearLogs();
      setLogs([]);
      setActionNotice("All telemetry and audit logs cleared.");
      setTimeout(() => setActionNotice(null), 3500);
    } catch (err: any) {
      setError("Failed to clear logs.");
    }
  };

  const toggleExpand = (logId: number) => {
    setExpandedLogIds((prev) => ({
      ...prev,
      [logId]: !prev[logId],
    }));
  };

  // Helper for source badge styling
  const getSourceBadgeClass = (source: string) => {
    switch (source.toUpperCase()) {
      case "EDR":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      case "XDR":
        return "bg-purple-500/10 text-purple-400 border-purple-500/30";
      case "SIEM":
        return "bg-indigo-500/10 text-indigo-400 border-indigo-500/30";
      case "TIP":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "FIREWALL":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "IAM":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "ITSM":
        return "bg-blue-500/10 text-blue-400 border-blue-500/30";
      case "AUTOMATION":
        return "bg-teal-500/10 text-teal-400 border-teal-500/30";
      default:
        return "bg-slate-700/20 text-slate-400 border-slate-700";
    }
  };

  // Helper for level badge styling
  const getLevelBadgeClass = (level: string) => {
    switch (level.toUpperCase()) {
      case "CRITICAL":
        return "bg-rose-600/20 text-rose-400 border-rose-500/40 animate-pulse font-black";
      case "ERROR":
        return "bg-red-500/10 text-red-400 border-red-500/30 font-bold";
      case "ACTION":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 font-bold";
      case "WARNING":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30 font-semibold";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700 font-medium";
    }
  };

  // Format relative elapsed time (seconds ago)
  const formatTimeAgo = (isoDate: string) => {
    const diffMs = Date.now() - new Date(isoDate).getTime();
    const diffSec = Math.max(0, Math.floor(diffMs / 1000));
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHour = Math.floor(diffMin / 60);
    return `${diffHour}h ago`;
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center space-x-3 mb-1">
            <div className="p-2.5 rounded-xl bg-blue-600/10 border border-blue-500/20 text-blue-400">
              <Terminal className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white flex items-center gap-2.5">
                Centralized Telemetry & Audit Logs
                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-400 font-bold border border-blue-500/30 font-mono">
                  LIVE STREAM
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                Unified security telemetry across EDR, XDR, Wazuh SIEM, Threat Intel, Firewall ACLs, and Autonomous Playbooks.
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Live Auto-Refresh Toggle */}
          <button
            onClick={() => setIsLiveStreaming(!isLiveStreaming)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition ${
              isLiveStreaming
                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                : "bg-slate-800 text-slate-400 border-slate-700"
            }`}
          >
            {isLiveStreaming ? (
              <>
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
                <span>Live Streaming (3s)</span>
              </>
            ) : (
              <>
                <Pause className="h-3.5 w-3.5" />
                <span>Stream Paused</span>
              </>
            )}
          </button>

          {/* Inject Test Telemetry Button */}
          <button
            onClick={handleSeedFreshLogs}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 rounded-xl text-xs font-semibold transition"
            title="Inject fresh real-time events to see live updates"
          >
            <Zap className="h-3.5 w-3.5 text-indigo-400" />
            <span>Inject Telemetry</span>
          </button>

          {/* Refresh Manual Button */}
          <button
            onClick={() => fetchLogs(true)}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-xl text-xs font-semibold transition"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-blue-400" : ""}`} />
            <span>Refresh</span>
          </button>

          {/* Clear Logs */}
          <button
            onClick={handleClearLogs}
            className="p-1.5 text-slate-400 hover:text-rose-400 bg-slate-900 hover:bg-rose-500/10 border border-slate-800 rounded-xl text-xs transition"
            title="Clear all logs"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Notifications */}
      {actionNotice && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center space-x-2 animate-in fade-in">
          <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
          <span>{actionNotice}</span>
        </div>
      )}

      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center space-x-2">
          <AlertCircle className="h-4 w-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* FILTER CONTROL CARD */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
        {/* ROW 1: Source Selector Pills */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400">
            <span className="flex items-center gap-1.5">
              <Filter className="h-3.5 w-3.5 text-blue-400" />
              Filter by Integration Connector / Source:
            </span>
            <span className="text-[11px] text-slate-500 font-mono">
              Selected: <strong className="text-blue-400">{selectedSource}</strong>
            </span>
          </div>

          <div className="flex flex-wrap gap-2">
            {SOURCES.map((src) => {
              const isSelected = selectedSource === src.id;
              const Icon = src.icon;
              return (
                <button
                  key={src.id}
                  onClick={() => setSelectedSource(src.id)}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-bold transition ${
                    isSelected
                      ? "bg-blue-600 text-white shadow-lg shadow-blue-600/25 border border-blue-500"
                      : "bg-slate-950 text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 border border-slate-800"
                  }`}
                >
                  {Icon && <Icon className="h-3.5 w-3.5 opacity-80" />}
                  <span>{src.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* ROW 2: Time Window Filter in Seconds */}
        <div className="pt-3 border-t border-slate-800/80 space-y-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-semibold text-slate-400">
            <span className="flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5 text-amber-400" />
              Filter by Time Window (Seconds):
            </span>
            <div className="flex items-center space-x-2">
              <span className="text-[11px] text-slate-500">
                Current Filter: <strong className="text-amber-400">{selectedSeconds === 0 ? "All Time" : `Last ${selectedSeconds} seconds`}</strong>
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Quick Presets */}
            {TIME_PRESETS.map((preset) => {
              const isSelected = selectedSeconds === preset.seconds && !customSecondsInput;
              return (
                <button
                  key={preset.seconds}
                  onClick={() => {
                    setSelectedSeconds(preset.seconds);
                    setCustomSecondsInput("");
                  }}
                  className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition ${
                    isSelected
                      ? "bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-sm"
                      : "bg-slate-950 text-slate-400 hover:text-slate-200 border-slate-800"
                  }`}
                >
                  {preset.label}
                </button>
              );
            })}

            {/* Custom Seconds Input Form */}
            <form onSubmit={handleApplyCustomSeconds} className="flex items-center space-x-1.5 ml-auto">
              <span className="text-[11px] text-slate-500">Custom (sec):</span>
              <input
                type="number"
                min="1"
                max="86400"
                value={customSecondsInput}
                onChange={(e) => setCustomSecondsInput(e.target.value)}
                placeholder="e.g. 45"
                className="w-20 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-amber-500 text-center font-mono"
              />
              <button
                type="submit"
                className="px-2.5 py-1 bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/30 rounded-lg text-xs font-bold transition"
              >
                Apply
              </button>
              {customSecondsInput && (
                <button
                  type="button"
                  onClick={() => {
                    setCustomSecondsInput("");
                    setSelectedSeconds(0);
                  }}
                  className="p-1 text-slate-500 hover:text-slate-300"
                  title="Clear custom time filter"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </form>
          </div>
        </div>

        {/* ROW 3: Search & Level Filter */}
        <div className="pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-3">
          {/* Keyword Search */}
          <div className="relative w-full sm:w-96">
            <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search in messages, targets, hashes, rule IDs..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Level Filter */}
          <div className="flex items-center space-x-2 w-full sm:w-auto">
            <span className="text-xs text-slate-400 font-medium">Level:</span>
            <select
              value={selectedLevel}
              onChange={(e) => setSelectedLevel(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-semibold"
            >
              <option value="ALL">All Levels</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="ERROR">ERROR</option>
              <option value="ACTION">ACTION</option>
              <option value="WARNING">WARNING</option>
              <option value="INFO">INFO</option>
            </select>
          </div>
        </div>
      </div>

      {/* TELEMETRY FEED LIST */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
        {/* Terminal Header */}
        <div className="p-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="h-3 w-3 rounded-full bg-rose-500/80 inline-block" />
            <span className="h-3 w-3 rounded-full bg-amber-500/80 inline-block" />
            <span className="h-3 w-3 rounded-full bg-emerald-500/80 inline-block" />
            <span className="text-xs font-mono text-slate-400 ml-2 font-bold">
              telemetry_stream.log
            </span>
          </div>

          <div className="text-xs font-mono text-slate-400">
            {logs.length} events logged
          </div>
        </div>

        {/* Events Container */}
        <div className="divide-y divide-slate-800/60 font-mono text-xs">
          {loading && logs.length === 0 ? (
            <div className="py-16 text-center text-slate-500 space-y-2">
              <RefreshCw className="h-6 w-6 animate-spin mx-auto text-blue-500" />
              <p>Streaming security telemetry events...</p>
            </div>
          ) : logs.length === 0 ? (
            <div className="py-16 text-center text-slate-500 space-y-3">
              <Terminal className="h-8 w-8 mx-auto text-slate-600" />
              <p className="text-slate-400 font-medium">
                No logs match the selected filter criteria.
              </p>
              <p className="text-[11px] text-slate-600">
                Try widening the time window or clearing the source, level and search filters.
              </p>
            </div>
          ) : (
            logs.map((log) => {
              const isExpanded = !!expandedLogIds[log.log_id];
              const sourceBadge = getSourceBadgeClass(log.source);
              const levelBadge = getLevelBadgeClass(log.level);
              const timeAgo = formatTimeAgo(log.created_at);

              return (
                <div 
                  key={log.log_id} 
                  className="p-4 hover:bg-slate-800/30 transition flex flex-col space-y-2 group"
                >
                  {/* Log Headline */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      {/* Timestamp & Elapsed */}
                      <span className="text-slate-500 text-[11px] font-mono whitespace-nowrap">
                        {new Date(log.created_at).toLocaleTimeString()} ({timeAgo})
                      </span>

                      {/* Source Badge */}
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sourceBadge}`}>
                        {log.source}
                      </span>

                      {/* Level Badge */}
                      <span className={`px-2 py-0.5 rounded text-[10px] border ${levelBadge}`}>
                        {log.level}
                      </span>

                      {/* Target Indicator */}
                      {log.target && (
                        <span className="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 text-[10px] border border-slate-700/80">
                          target: <strong className="text-blue-300">{log.target}</strong>
                        </span>
                      )}
                    </div>

                    {/* Expand Details Toggle */}
                    {log.details && Object.keys(log.details).length > 0 && (
                      <button
                        onClick={() => toggleExpand(log.log_id)}
                        className="text-[11px] text-slate-500 hover:text-slate-300 flex items-center space-x-1"
                      >
                        <span>{isExpanded ? "Hide Payload" : "View Payload"}</span>
                        {isExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                      </button>
                    )}
                  </div>

                  {/* Message */}
                  <div className="text-slate-200 text-xs font-sans font-medium pl-1 leading-relaxed">
                    {log.message}
                  </div>

                  {/* Expandable JSON Payload Drawer */}
                  {isExpanded && log.details && (
                    <div className="mt-2 p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                      <div className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-1.5">
                        Raw Telemetry JSON
                      </div>
                      <pre className="text-emerald-400">
                        {JSON.stringify(log.details, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
