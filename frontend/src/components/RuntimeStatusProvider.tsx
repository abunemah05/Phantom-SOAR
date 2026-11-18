"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import { usePolling } from "@/hooks/usePolling";
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
      setStatus(await api.getRuntimeStatus());
      setError(null);
    } catch (err) {
      // Keep the last known status (if any) but surface the failure instead of hiding it.
      setError(describeError(err, "Runtime status unavailable."));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Paused while the tab is hidden; refreshes once when it becomes visible again.
  usePolling(() => void refresh(), POLL_INTERVAL_MS);

  const value = useMemo(() => ({ status, error, refresh }), [status, error, refresh]);
  return <RuntimeStatusContext.Provider value={value}>{children}</RuntimeStatusContext.Provider>;
}

export function useRuntimeStatus(): RuntimeStatusContextValue {
  return useContext(RuntimeStatusContext);
}
