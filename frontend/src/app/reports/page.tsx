"use client";

import React, { useState, useEffect } from "react";
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
import { AdminReportData, User } from "@/lib/types";
import { getStoredUser, subscribeToAuth } from "@/lib/auth";

export default function AdminReportsPage() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isAuthorized, setIsAuthorized] = useState<boolean>(true);
  
  // Filter States
  const [period, setPeriod] = useState<string>("month");
  const [selectedAnalyst, setSelectedAnalyst] = useState<string>("all");
  const [startDate, setStartDate] = useState<string>("");
  const [endDate, setEndDate] = useState<string>("");
  const [analysts, setAnalysts] = useState<Array<{ username: string; role: string }>>([]);

  // Data & Loading States
  const [report, setReport] = useState<AdminReportData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const evaluateAuth = (user: User | null) => {
    setCurrentUser(user);
    if (!user) {
      setIsAuthorized(false);
      return false;
    }
    const roleLower = (user.role || "").toLowerCase();
    const authorized = roleLower.includes("admin") || roleLower.includes("lead");
    setIsAuthorized(authorized);
    return authorized;
  };

  useEffect(() => {
    const user = getStoredUser();
    evaluateAuth(user);

    const unsubscribe = subscribeToAuth((updatedUser) => {
      evaluateAuth(updatedUser);
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const loadAnalysts = async () => {
    try {
      const list = await api.getAvailableAnalysts();
      setAnalysts(list);
    } catch {
      // fallback
    }
  };

  const loadReport = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getAdminReport({
        analyst: selectedAnalyst,
        period,
        start_date: period === "custom" ? startDate : undefined,
        end_date: period === "custom" ? endDate : undefined,
      });
      setReport(data);
    } catch (err: any) {
      setError(err.message || "Failed to load admin reporting analytics.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAnalysts();
    loadReport();
  }, [period, selectedAnalyst]);

  const handleApplyCustomFilter = (e: React.FormEvent) => {
    e.preventDefault();
    loadReport();
  };

  if (!isAuthorized) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh] text-center px-4">
        <div className="h-16 w-16 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 mb-4">
          <Lock className="h-8 w-8" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">Access Restricted (Admin Only)</h2>
        <p className="text-sm text-slate-400 max-w-md">
          The Reporting & Audit Engine is restricted to SOC Administrators. Your operator role is <b>{currentUser?.role || "SOC Analyst"}</b>.
        </p>
      </div>
    );
  }

  const pdfDownloadUrl = api.getAdminReportPdfUrl({
    analyst: selectedAnalyst,
    period,
    start_date: period === "custom" ? startDate : undefined,
    end_date: period === "custom" ? endDate : undefined,
  });

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
          <a
            href={pdfDownloadUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center space-x-2 px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-lg shadow-blue-600/20 transition duration-150"
          >
            <Download className="h-4 w-4" />
            <span>Export Executive PDF Report</span>
          </a>
          <button
            onClick={loadReport}
            disabled={loading}
            className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 transition"
            title="Refresh Report Data"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-blue-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filter Toolbar (Calendar & Analyst Selector) */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Quick Period Tabs */}
          <div className="flex items-center space-x-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800/80">
            {[
              { id: "day", label: "Today (24h)" },
              { id: "week", label: "Past 7 Days" },
              { id: "month", label: "Past 30 Days" },
              { id: "custom", label: "Custom Range" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setPeriod(tab.id)}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition ${
                  period === tab.id
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
              value={selectedAnalyst}
              onChange={(e) => setSelectedAnalyst(e.target.value)}
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

        {/* Custom Date Picker Inputs (Visible when 'custom' is active) */}
        {period === "custom" && (
          <form onSubmit={handleApplyCustomFilter} className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-3">
            <div className="flex items-center space-x-2 text-xs text-slate-300">
              <Calendar className="h-4 w-4 text-blue-400" />
              <span>Start Date:</span>
              <input
                type="date"
                required
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-white text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>

            <div className="flex items-center space-x-2 text-xs text-slate-300">
              <span>End Date:</span>
              <input
                type="date"
                required
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-white text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>

            <button
              type="submit"
              className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition"
            >
              Apply Filter
            </button>
          </form>
        )}
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

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
          <span className="text-[11px] text-slate-500 mt-1 block">In selected period</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-1">
            <span>Containment Executions</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-400">
            {report?.total_containment_actions ?? 0}
          </div>
          <span className="text-[11px] text-slate-500 mt-1 block">Host & IP isolations</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-1">
            <span>Average MTTR</span>
            <Clock className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black text-amber-400">
            {report?.average_mttr_seconds ? `${report.average_mttr_seconds}s` : "0.0s"}
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

      {/* Analyst Decision & Performance Matrix Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className="h-4 w-4 text-blue-400" />
            <h3 className="text-sm font-bold text-white">Analyst Performance & Decision Matrix (HITL Actions)</h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Range: {report?.start_date.substring(0, 10)} to {report?.end_date.substring(0, 10)}
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
                    <td className="py-3 px-4 font-mono text-slate-300">{a.avg_mttr_seconds}s</td>
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
                      {c.resolved_by || "Autonomous"}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 max-w-xs truncate">
                      {c.analyst_decision || "Autonomous Engine"}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[11px] text-slate-500">
                      {c.created_at ? c.created_at.substring(0, 19).replace("T", " ") : "-"}
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
    </div>
  );
}
