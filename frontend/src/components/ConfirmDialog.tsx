"use client";

import React, { createContext, useCallback, useContext, useRef, useState } from "react";
import { AlertTriangle, ShieldAlert } from "lucide-react";
import Dialog from "./Dialog";

export interface ConfirmOptions {
  title: string;
  /** State exactly what will happen. */
  message: React.ReactNode;
  /** Bullet list under the message (consequences, or blockers when `hideCancel` is set). */
  items?: string[];
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: "danger" | "warning" | "default";
  /** The operator must type this exact text before the confirm button is enabled (irreversible actions). */
  requireText?: string;
  /** Show only an acknowledge button (used to display refusals such as HOTL blockers). */
  hideCancel?: boolean;
}

type ConfirmFn = (options: ConfirmOptions) => Promise<boolean>;

const ConfirmContext = createContext<ConfirmFn>(() => Promise.resolve(false));

/** `const confirm = useConfirm(); if (!(await confirm({...}))) return;` */
export function useConfirm(): ConfirmFn {
  return useContext(ConfirmContext);
}

const TONE_BUTTON: Record<string, string> = {
  danger: "bg-rose-600 hover:bg-rose-500 text-white focus-visible:ring-rose-400",
  warning: "bg-amber-600 hover:bg-amber-500 text-white focus-visible:ring-amber-400",
  default: "bg-blue-600 hover:bg-blue-500 text-white focus-visible:ring-blue-400",
};

export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const [options, setOptions] = useState<ConfirmOptions | null>(null);
  const [typed, setTyped] = useState("");
  const resolver = useRef<((value: boolean) => void) | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const confirm = useCallback<ConfirmFn>((next) => {
    // A second request while one is open cancels the first.
    resolver.current?.(false);
    setTyped("");
    setOptions(next);
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve;
    });
  }, []);

  const settle = (value: boolean) => {
    resolver.current?.(value);
    resolver.current = null;
    setOptions(null);
    setTyped("");
  };

  const tone = options?.tone ?? "default";
  const needsText = Boolean(options?.requireText);
  const canConfirm = !needsText || typed === options?.requireText;
  const Icon = tone === "danger" ? ShieldAlert : AlertTriangle;
  const iconColor = tone === "danger" ? "text-rose-400 bg-rose-500/10 border-rose-500/30" : tone === "warning" ? "text-amber-400 bg-amber-500/10 border-amber-500/30" : "text-blue-400 bg-blue-500/10 border-blue-500/30";

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <Dialog
        open={options !== null}
        onClose={() => settle(false)}
        title={options?.title ?? ""}
        role="alertdialog"
        size="md"
        initialFocusRef={needsText ? inputRef : cancelRef}
        icon={
          <div className={`h-9 w-9 flex-shrink-0 rounded-xl border flex items-center justify-center ${iconColor}`}>
            <Icon className="h-5 w-5" />
          </div>
        }
        footer={
          <>
            {!options?.hideCancel && (
              <button
                ref={cancelRef}
                type="button"
                onClick={() => settle(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                {options?.cancelLabel ?? "Cancel"}
              </button>
            )}
            <button
              ref={options?.hideCancel ? cancelRef : undefined}
              type="button"
              disabled={!canConfirm}
              onClick={() => settle(true)}
              className={`px-4 py-2 rounded-lg text-xs font-bold disabled:opacity-40 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 ${TONE_BUTTON[tone]}`}
            >
              {options?.confirmLabel ?? (options?.hideCancel ? "OK" : "Confirm")}
            </button>
          </>
        }
      >
        <div className="text-sm text-slate-300 leading-relaxed">{options?.message}</div>
        {options?.items && options.items.length > 0 && (
          <ul className="list-disc list-inside space-y-1 text-xs text-slate-300 bg-slate-950/60 border border-slate-800 rounded-lg p-3">
            {options.items.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        )}
        {needsText && (
          <div className="space-y-1">
            <label htmlFor="confirm-typed" className="text-xs font-semibold text-slate-300">
              Type <code className="font-mono text-rose-300">{options?.requireText}</code> to confirm
            </label>
            <input
              id="confirm-typed"
              ref={inputRef}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono text-white focus:outline-none focus:ring-2 focus:ring-rose-500"
            />
          </div>
        )}
      </Dialog>
    </ConfirmContext.Provider>
  );
}
