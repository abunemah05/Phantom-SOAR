"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { describeError } from "@/lib/errors";
import { usePolling } from "./usePolling";

export interface ResourceState<T> {
  data: T | null;
  /** Message of the last failed load. Stale data (if any) is kept so the view does not blank on a blip. */
  error: string | null;
  /** True only for the first load and for explicit reloads, not for background polls. */
  loading: boolean;
  /** When the data was last loaded successfully. */
  loadedAt: number | null;
  reload: () => Promise<void>;
}

/**
 * Load data with real loading / error states. `fetcher` must be stable (useCallback); a new fetcher reloads.
 * With `pollMs` the data is refreshed in the background, paused while the tab is hidden.
 * Failures are never swallowed: they become `error`, and the previous data stays visible next to it.
 */
export function useResource<T>(
  fetcher: () => Promise<T>,
  options?: { pollMs?: number; enabled?: boolean }
): ResourceState<T> {
  const enabled = options?.enabled ?? true;
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(enabled);
  const [loadedAt, setLoadedAt] = useState<number | null>(null);
  const requestId = useRef(0);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(
    async (showLoading: boolean) => {
      const id = ++requestId.current;
      if (showLoading) setLoading(true);
      try {
        const next = await fetcher();
        if (!mounted.current || id !== requestId.current) return;
        setData(next);
        setError(null);
        setLoadedAt(Date.now());
      } catch (err) {
        if (!mounted.current || id !== requestId.current) return;
        setError(describeError(err, "Could not load data."));
      } finally {
        if (mounted.current && id === requestId.current) setLoading(false);
      }
    },
    [fetcher]
  );

  useEffect(() => {
    if (enabled) void run(true);
    else setLoading(false);
  }, [enabled, run]);

  usePolling(() => void run(false), options?.pollMs ?? 0, enabled && Boolean(options?.pollMs));

  const reload = useCallback(() => run(true), [run]);
  return { data, error, loading, loadedAt, reload };
}
