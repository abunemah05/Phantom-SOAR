/** Human-readable duration for MTTR values (real seconds from alert creation to completion). */
export function formatDuration(seconds?: number | null): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds <= 0) {
    return "—";
  }
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 2 : 1)}s`;
  const totalSeconds = Math.round(seconds);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const secs = totalSeconds % 60;
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m ${secs}s`;
}

const HAS_TIMEZONE = /(Z|[+-]\d{2}:?\d{2})$/i;

/**
 * Parse a timestamp from the API. The backend stores UTC and some columns serialise
 * without an offset ("2026-11-10T12:11:23"); those are treated as UTC, not local time.
 */
export function parseApiDate(value?: string | null): Date | null {
  if (!value) return null;
  const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(value) && !HAS_TIMEZONE.test(value) ? `${value}Z` : value;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatDateTime(value?: string | null, fallback = "—"): string {
  const d = parseApiDate(value);
  return d ? d.toLocaleString() : fallback;
}

export function formatDate(value?: string | null, fallback = "—"): string {
  const d = parseApiDate(value);
  return d ? d.toLocaleDateString() : fallback;
}

export function formatTimeOfDay(value?: string | null, fallback = "—"): string {
  const d = parseApiDate(value);
  return d ? d.toLocaleTimeString() : fallback;
}
