"use client";

import { useEffect, useRef, useState } from "react";

/** True while the browser tab is visible. */
export function usePageVisible(): boolean {
  const [visible, setVisible] = useState<boolean>(() =>
    typeof document === "undefined" ? true : document.visibilityState !== "hidden"
  );
  useEffect(() => {
    const onChange = () => setVisible(document.visibilityState !== "hidden");
    document.addEventListener("visibilitychange", onChange);
    return () => document.removeEventListener("visibilitychange", onChange);
  }, []);
  return visible;
}

/**
 * Call `callback` every `intervalMs` while the tab is visible and `enabled` is true. Nothing runs while the tab
 * is hidden; when it becomes visible again the callback fires once immediately so the view is current.
 */
export function usePolling(callback: () => void, intervalMs: number, enabled: boolean = true): void {
  const saved = useRef(callback);
  useEffect(() => {
    saved.current = callback;
  }, [callback]);

  const visible = usePageVisible();
  const wasHidden = useRef(false);

  useEffect(() => {
    if (!enabled) return;
    if (!visible) {
      wasHidden.current = true;
      return;
    }
    if (wasHidden.current) {
      wasHidden.current = false;
      saved.current();
    }
    const id = setInterval(() => saved.current(), intervalMs);
    return () => clearInterval(id);
  }, [enabled, intervalMs, visible]);
}
