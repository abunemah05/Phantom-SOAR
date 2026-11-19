"use client";

import React, { useCallback, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import Dialog from "./Dialog";
import { InlineNotice } from "./StateViews";
import { buildConfirmation, validateStepUpInput } from "@/lib/accountPolicy";
import { StepUpConfirmation } from "@/lib/types";

// Re-confirmation for sensitive account changes (docs/ACCESS_CONTROL.md, rule R5): the signed-in administrator
// re-enters their OWN password (and a current MFA code when they use MFA). The server verifies it and refuses the
// change otherwise; this dialog only collects the values. Nothing is stored: the secrets live in component state
// until the dialog closes.

export interface StepUpAsk {
  title: string;
  /** What is about to happen and why a confirmation is needed. */
  reason: string;
  /** Shown when an earlier confirmation was rejected by the server. */
  error?: string | null;
  confirmLabel?: string;
}

const INPUT =
  "w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500";

/**
 * `const { askStepUp, stepUpDialog } = useStepUp(user.mfa_enabled)` then `const conf = await askStepUp({...})`
 * (null when cancelled). Render `{stepUpDialog}` once in the page.
 */
export function useStepUp(needsMfa: boolean): { askStepUp: (ask: StepUpAsk) => Promise<StepUpConfirmation | null>; stepUpDialog: React.ReactNode } {
  const [ask, setAsk] = useState<StepUpAsk | null>(null);
  const resolver = useRef<((value: StepUpConfirmation | null) => void) | null>(null);

  const askStepUp = useCallback((next: StepUpAsk) => {
    resolver.current?.(null); // a second request replaces an open one
    setAsk(next);
    return new Promise<StepUpConfirmation | null>((resolve) => {
      resolver.current = resolve;
    });
  }, []);

  const settle = useCallback((value: StepUpConfirmation | null) => {
    resolver.current?.(value);
    resolver.current = null;
    setAsk(null);
  }, []);

  const stepUpDialog = <StepUpForm ask={ask} needsMfa={needsMfa} onSettle={settle} />;
  return { askStepUp, stepUpDialog };
}

function StepUpForm({ ask, needsMfa, onSettle }: { ask: StepUpAsk | null; needsMfa: boolean; onSettle: (value: StepUpConfirmation | null) => void }) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const firstRef = useRef<HTMLInputElement>(null);

  const finish = (value: StepUpConfirmation | null) => {
    setPassword("");
    setCode("");
    setLocalError(null);
    onSettle(value);
  };

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const problem = validateStepUpInput(password, code, needsMfa);
    if (problem) {
      setLocalError(problem);
      return;
    }
    finish(buildConfirmation(password, code, needsMfa));
  };

  const error = localError || ask?.error || null;

  return (
    <Dialog
      open={ask !== null}
      onClose={() => finish(null)}
      title={ask?.title ?? "Confirm this change"}
      description={ask?.reason}
      size="sm"
      role="alertdialog"
      initialFocusRef={firstRef}
      icon={<ShieldCheck className="h-5 w-5 text-amber-300 mt-0.5" aria-hidden="true" />}
    >
      <form onSubmit={submit} className="space-y-4" autoComplete="off">
        {error && <InlineNotice tone="error">{error}</InlineNotice>}
        <p className="text-[11px] text-slate-400 leading-relaxed">
          Changes to another administrator, or a grant of the Admin role, are privileged. Enter <b>your own</b> password
          {needsMfa ? " and a current code from your authenticator app" : ""} to continue. The change is recorded in the audit log under your name.
        </p>
        <div className="space-y-1.5">
          <label htmlFor="stepup-password" className="text-xs font-semibold text-slate-300">Your password</label>
          <input
            ref={firstRef}
            id="stepup-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={INPUT}
          />
        </div>
        {needsMfa && (
          <div className="space-y-1.5">
            <label htmlFor="stepup-code" className="text-xs font-semibold text-slate-300">Authenticator code</label>
            <input
              id="stepup-code"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={8}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="123456"
              className={INPUT}
            />
          </div>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={() => finish(null)} className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
            Cancel
          </button>
          <button type="submit" className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold flex items-center gap-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-300">
            {ask?.confirmLabel ?? "Confirm change"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
