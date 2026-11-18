"use client";

import React, { useEffect, useState } from "react";
import { Check, Copy, KeyRound } from "lucide-react";
import Dialog from "./Dialog";

export interface OneTimeSecret {
  /** What it is, e.g. "API key for triage-agent". */
  title: string;
  /** The secret. Held in memory only for as long as the dialog is open. */
  value: string;
  /** Plain-language warning and usage note. */
  note: React.ReactNode;
}

/**
 * Shows a secret that the backend returns exactly once (API key, ingest token, temporary password).
 * It cannot be dismissed by Escape or a backdrop click: the operator must acknowledge having stored it.
 */
export default function SecretOnceDialog({ secret, onDone }: { secret: OneTimeSecret | null; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);

  useEffect(() => {
    setCopied(false);
    setCopyError(false);
  }, [secret?.value]);

  const copy = async () => {
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret.value);
      setCopied(true);
      setCopyError(false);
    } catch {
      setCopyError(true); // clipboard blocked: the value is selectable below
    }
  };

  return (
    <Dialog
      open={secret !== null}
      onClose={onDone}
      title={secret?.title ?? ""}
      dismissible={false}
      hideCloseButton
      size="lg"
      icon={
        <div className="h-9 w-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-300 flex-shrink-0">
          <KeyRound className="h-5 w-5" />
        </div>
      }
      footer={
        <button
          type="button"
          onClick={onDone}
          className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
        >
          I have stored it
        </button>
      }
    >
      <p className="text-xs text-amber-300 font-semibold">
        This value is shown once. It is not stored in a recoverable form, so it cannot be displayed again.
      </p>
      <div className="flex items-center gap-2">
        <code className="flex-1 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-200 break-all select-all">
          {secret?.value}
        </code>
        <button
          type="button"
          onClick={copy}
          aria-label="Copy to clipboard"
          className="p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
        </button>
      </div>
      <div aria-live="polite" className="text-[11px] text-slate-400 min-h-[1rem]">
        {copied && "Copied to clipboard."}
        {copyError && "Clipboard access was blocked; select the value above and copy it manually."}
      </div>
      <div className="text-[11px] text-slate-400 leading-relaxed">{secret?.note}</div>
    </Dialog>
  );
}
