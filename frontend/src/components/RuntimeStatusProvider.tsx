"use client";

import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { RuntimeStatus } from "@/lib/types";

interface RuntimeStatusContextValue {
  /** null until loaded, or when the backend could not be reached. */
  status: RuntimeStatus | null;
  error: string | null;
  refresh: () => Promise<void>;
}

const RuntimeStatusContext = createContext<RuntimeStatusContextValue>({
  status: null,
  error: null,
  refresh: async () => {},
});

const POLL_INTERVAL_MS = 30_000;

export function RuntimeStatusProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<RuntimeStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const next = await api.getRuntimeStatus();
      setStatus(next);
      setError(null);
    } catch (err: any) {
      setError(err?.message || "Runtime status unavailable.");
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [refresh]);

  return (
    <RuntimeStatusContext.Provider value={{ status, error, refresh }}>
      {children}
    </RuntimeStatusContext.Provider>
  );
}

export function useRuntimeStatus(): RuntimeStatusContextValue {
  return useContext(RuntimeStatusContext);
}
