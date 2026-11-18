"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";

type ToastKind = "success" | "error" | "info";

interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
}

interface ToastApi {
  success: (message: string) => void;
  error: (message: string) => void;
  info: (message: string) => void;
}

const noop = () => {};
const ToastContext = createContext<ToastApi>({ success: noop, error: noop, info: noop });

export function useToast(): ToastApi {
  return useContext(ToastContext);
}

const TIMEOUT_MS: Record<ToastKind, number> = { success: 6000, info: 6000, error: 12000 };
const MAX_TOASTS = 4;

const STYLE: Record<ToastKind, string> = {
  success: "border-emerald-500/40 text-emerald-200",
  info: "border-blue-500/40 text-blue-200",
  error: "border-rose-500/50 text-rose-200",
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);
  const timers = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: number) => {
    setItems((prev) => prev.filter((t) => t.id !== id));
    const timer = timers.current.get(id);
    if (timer) clearTimeout(timer);
    timers.current.delete(id);
  }, []);

  const push = useCallback(
    (kind: ToastKind, message: string) => {
      const id = nextId.current++;
      setItems((prev) => [...prev.slice(-(MAX_TOASTS - 1)), { id, kind, message }]);
      timers.current.set(id, setTimeout(() => dismiss(id), TIMEOUT_MS[kind]));
    },
    [dismiss]
  );

  useEffect(() => {
    const active = timers.current;
    return () => active.forEach((t) => clearTimeout(t));
  }, []);

  // Stable object identity so consumers can list it in hook dependencies without re-running effects.
  const api = useMemo<ToastApi>(
    () => ({
      success: (m) => push("success", m),
      error: (m) => push("error", m),
      info: (m) => push("info", m),
    }),
    [push]
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      {/* Live region: screen readers announce new toasts; errors are assertive. */}
      <div className="fixed bottom-4 right-4 z-[80] flex flex-col gap-2 w-[min(24rem,calc(100vw-2rem))] pointer-events-none">
        <div aria-live="polite" role="status" className="flex flex-col gap-2">
          {items
            .filter((t) => t.kind !== "error")
            .map((t) => (
              <ToastCard key={t.id} item={t} onDismiss={dismiss} />
            ))}
        </div>
        <div aria-live="assertive" role="alert" className="flex flex-col gap-2">
          {items
            .filter((t) => t.kind === "error")
            .map((t) => (
              <ToastCard key={t.id} item={t} onDismiss={dismiss} />
            ))}
        </div>
      </div>
    </ToastContext.Provider>
  );
}

function ToastCard({ item, onDismiss }: { item: ToastItem; onDismiss: (id: number) => void }) {
  const Icon = item.kind === "success" ? CheckCircle2 : item.kind === "error" ? AlertCircle : Info;
  return (
    <div className={`pointer-events-auto flex items-start gap-2.5 rounded-xl border bg-slate-900 px-3.5 py-3 text-xs shadow-xl shadow-black/50 animate-fade-in ${STYLE[item.kind]}`}>
      <Icon className="h-4 w-4 flex-shrink-0 mt-0.5" aria-hidden="true" />
      <span className="flex-1 leading-relaxed break-words">{item.message}</span>
      <button
        type="button"
        onClick={() => onDismiss(item.id)}
        aria-label="Dismiss notification"
        className="text-slate-400 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}
