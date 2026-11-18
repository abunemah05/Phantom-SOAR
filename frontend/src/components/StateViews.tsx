"use client";

import React from "react";
import { AlertCircle, RefreshCw } from "lucide-react";

export function LoadingState({ label = "Loading..." }: { label?: string }) {
  return (
    <div role="status" className="flex flex-col items-center justify-center py-16 space-y-3 text-slate-400">
      <div className="animate-spin rounded-full h-7 w-7 border-b-2 border-blue-500" aria-hidden="true" />
      <p className="text-sm">{label}</p>
    </div>
  );
}

/** A failed load. Always offers a retry; never shows fake or empty data in its place. */
export function ErrorState({
  title = "Could not load this data",
  message,
  onRetry,
  compact = false,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
  compact?: boolean;
}) {
  return (
    <div
      role="alert"
      className={`rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 ${compact ? "p-3" : "p-6"} flex items-start gap-3`}
    >
      <AlertCircle className="h-5 w-5 flex-shrink-0 mt-0.5 text-rose-400" aria-hidden="true" />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-bold text-rose-200">{title}</p>
        <p className="text-xs mt-1 break-words">{message}</p>
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-100 text-xs font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
          Retry
        </button>
      )}
    </div>
  );
}

/** Stale data is still on screen but the last refresh failed. */
export function StaleBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-center justify-between gap-3 rounded-lg bg-amber-500/10 border border-amber-500/30 px-3 py-2 text-xs text-amber-200">
      <span>Showing the last data that loaded. Refresh failed: {message}</span>
      {onRetry && (
        <button type="button" onClick={onRetry} className="font-semibold underline hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 rounded">
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  children,
}: {
  icon?: React.ElementType;
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-14 px-4 text-center space-y-2.5">
      {Icon && (
        <div className="h-11 w-11 rounded-xl bg-slate-800/80 border border-slate-700/80 flex items-center justify-center text-slate-400">
          <Icon className="h-5 w-5" aria-hidden="true" />
        </div>
      )}
      <p className="text-sm font-semibold text-slate-300">{title}</p>
      {children && <div className="text-xs text-slate-500 max-w-md">{children}</div>}
    </div>
  );
}

export function AccessDenied({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center px-4">
      <h2 className="text-xl font-bold text-white mb-2">{title}</h2>
      <p className="text-sm text-slate-400 max-w-md">{children}</p>
    </div>
  );
}

export function InlineNotice({
  tone,
  children,
  onDismiss,
}: {
  tone: "error" | "success" | "info" | "warning";
  children: React.ReactNode;
  onDismiss?: () => void;
}) {
  const style = {
    error: "bg-rose-500/10 border-rose-500/30 text-rose-300",
    success: "bg-emerald-500/10 border-emerald-500/30 text-emerald-300",
    info: "bg-blue-500/10 border-blue-500/30 text-blue-200",
    warning: "bg-amber-500/10 border-amber-500/30 text-amber-200",
  }[tone];
  return (
    <div role={tone === "error" ? "alert" : "status"} className={`rounded-xl border p-3.5 text-xs flex items-start justify-between gap-3 ${style}`}>
      <div className="min-w-0 break-words">{children}</div>
      {onDismiss && (
        <button type="button" onClick={onDismiss} aria-label="Dismiss message" className="text-slate-400 hover:text-white flex-shrink-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded">
          &#10005;
        </button>
      )}
    </div>
  );
}
