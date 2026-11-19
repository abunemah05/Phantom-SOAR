// Filter model and validation for the admin Reports page (pure helpers, no DOM).
//
// Time semantics, mirrored from backend/routers/reports.py:
//   * The operator enters local date-times (<input type="datetime-local" step="1">, seconds supported).
//   * They are converted in the browser to UTC ISO-8601 ("2026-11-19T10:00:05Z") before being sent, so the
//     backend never has to guess a time zone. The backend answers (and the PDF prints) the exact range in UTC.
//   * A range is a closed interval [start, end]; end must be after start; at most 366 days.
//   * "Last N seconds/minutes/hours/days" is sent as last_n + last_unit and resolved by the server against its
//     own clock (end = now), so a clock skew between browser and server cannot shift the range.

export const SEVERITIES = ["Critical", "High", "Medium", "Low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const RELATIVE_UNITS = ["seconds", "minutes", "hours", "days"] as const;
export type RelativeUnit = (typeof RELATIVE_UNITS)[number];

export const REPORT_PERIODS = ["day", "week", "month", "relative", "custom"] as const;
export type ReportPeriod = (typeof REPORT_PERIODS)[number];

export const MAX_RANGE_DAYS = 366;
export const MIN_YEAR = 2000;
const MAX_RANGE_MS = MAX_RANGE_DAYS * 86_400_000;
const UNIT_SECONDS: Record<RelativeUnit, number> = { seconds: 1, minutes: 60, hours: 3600, days: 86_400 };

export interface ReportFilters {
  period: ReportPeriod;
  analyst: string; // username or "all"
  /** Empty means every severity. */
  severities: Severity[];
  /** datetime-local values: "YYYY-MM-DDTHH:mm" or "YYYY-MM-DDTHH:mm:ss", in the browser's local zone. */
  customStart: string;
  customEnd: string;
  relativeValue: string; // kept as text while typing
  relativeUnit: RelativeUnit;
}

export const DEFAULT_FILTERS: ReportFilters = {
  period: "month",
  analyst: "all",
  severities: [],
  customStart: "",
  customEnd: "",
  relativeValue: "15",
  relativeUnit: "minutes",
};

/** Query parameters for GET /reports/analyst-activity[/pdf]. */
export interface ReportQueryParams {
  analyst?: string;
  period?: string;
  start_date?: string;
  end_date?: string;
  last_n?: number;
  last_unit?: string;
  severity?: string[];
}

export type FilterCheck = { ok: true; params: ReportQueryParams } | { ok: false; error: string };

// ---------------------------------------------------------------------------------------------- severity

/** Canonical order (most severe first), no duplicates, unknown values dropped; all four selected = no filter. */
export function normaliseSeverities(selected: readonly string[]): Severity[] {
  const wanted = new Set(selected.map((s) => String(s).trim().toLowerCase()));
  const picked = SEVERITIES.filter((s) => wanted.has(s.toLowerCase()));
  return picked.length === SEVERITIES.length ? [] : picked;
}

/** True when `severity` is the only one selected: unticking it is refused (an empty selection would silently turn into
 *  "All", the opposite of what the operator just did). To see every severity, tick "All" explicitly. */
export function isLastSelectedSeverity(selected: readonly Severity[], severity: Severity): boolean {
  return selected.length === 1 && selected[0] === severity;
}

export function toggleSeverity(selected: readonly Severity[], severity: Severity): Severity[] {
  if (isLastSelectedSeverity(selected, severity)) return [...selected]; // at least one stays selected
  const next = selected.length === 0 ? [...SEVERITIES] : [...selected]; // from "All", unticking one leaves the rest
  const index = next.indexOf(severity);
  if (index >= 0) next.splice(index, 1);
  else next.push(severity);
  return normaliseSeverities(next);
}

export function describeSeverities(selected: readonly string[] | null | undefined): string {
  return selected && selected.length > 0 ? selected.join(", ") : "All severities";
}

// ---------------------------------------------------------------------------------------------- local time

const LOCAL_INPUT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/;

/** Strictly parse a datetime-local value as LOCAL time. Null when malformed, impossible (Feb 30) or nonexistent
 *  (inside a daylight-saving gap). An ambiguous time (clock set back) resolves to its first occurrence. */
export function parseLocalInput(value: string): Date | null {
  const m = LOCAL_INPUT.exec((value || "").trim());
  if (!m) return null;
  const [y, mo, d, h, mi, s] = [m[1], m[2], m[3], m[4], m[5], m[6] ?? "0"].map(Number);
  const date = new Date(y, mo - 1, d, h, mi, s, 0);
  if (
    Number.isNaN(date.getTime()) ||
    date.getFullYear() !== y ||
    date.getMonth() !== mo - 1 ||
    date.getDate() !== d ||
    date.getHours() !== h ||
    date.getMinutes() !== mi ||
    date.getSeconds() !== s
  ) {
    return null;
  }
  return date;
}

/** "2026-11-19T10:00:05" (local) -> "2026-11-19T09:00:05Z" (UTC), or null when invalid. */
export function localInputToUtcIso(value: string): string | null {
  const date = parseLocalInput(value);
  return date ? date.toISOString().replace(/\.000Z$/, "Z") : null;
}

/** Current local time as a datetime-local value (to the second). */
export function toLocalInput(date: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())}T${p(date.getHours())}:${p(date.getMinutes())}:${p(date.getSeconds())}`;
}

/** "Europe/Berlin (UTC+01:00)" for the browser's zone at the given moment. */
export function timeZoneLabel(at: Date = new Date()): string {
  const offsetMin = -at.getTimezoneOffset();
  const sign = offsetMin >= 0 ? "+" : "-";
  const abs = Math.abs(offsetMin);
  const offset = `UTC${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
  let zone = "";
  try {
    zone = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch {
    zone = "";
  }
  return zone ? `${zone} (${offset})` : offset;
}

// ---------------------------------------------------------------------------------------------- relative

/** The largest N that stays within MAX_RANGE_DAYS for a unit. */
export function maxRelativeValue(unit: RelativeUnit): number {
  return Math.floor((MAX_RANGE_DAYS * 86_400) / UNIT_SECONDS[unit]);
}

export function parseRelativeValue(text: string): number | null {
  const t = (text || "").trim();
  if (!/^\d{1,9}$/.test(t)) return null;
  const n = Number(t);
  return n >= 1 ? n : null;
}

// ---------------------------------------------------------------------------------------------- validation

function baseParams(f: ReportFilters): ReportQueryParams {
  const params: ReportQueryParams = { analyst: f.analyst || "all", period: f.period };
  const severities = normaliseSeverities(f.severities);
  if (severities.length > 0) params.severity = severities;
  return params;
}

/** Validate the filters and build the request parameters (custom bounds become UTC ISO-8601). */
export function validateFilters(f: ReportFilters): FilterCheck {
  const params = baseParams(f);

  if (f.period === "relative") {
    const n = parseRelativeValue(f.relativeValue);
    if (n === null) return { ok: false, error: "Enter a whole number of at least 1 for the relative range." };
    const max = maxRelativeValue(f.relativeUnit);
    if (n > max) {
      return { ok: false, error: `At most ${MAX_RANGE_DAYS} days can be reported: use ${max.toLocaleString("en-US")} ${f.relativeUnit} or fewer.` };
    }
    return { ok: true, params: { ...params, last_n: n, last_unit: f.relativeUnit } };
  }

  if (f.period === "custom") {
    if (!f.customStart.trim()) return { ok: false, error: "Enter a start date and time." };
    const start = parseLocalInput(f.customStart);
    if (!start) {
      return { ok: false, error: "The start is not a valid date and time (it may not exist in your time zone, e.g. a clock change)." };
    }
    if (start.getFullYear() < MIN_YEAR) return { ok: false, error: `Dates before ${MIN_YEAR} are not supported.` };
    let end: Date | null = null;
    if (f.customEnd.trim()) {
      end = parseLocalInput(f.customEnd);
      if (!end) {
        return { ok: false, error: "The end is not a valid date and time (it may not exist in your time zone, e.g. a clock change)." };
      }
      if (end.getTime() <= start.getTime()) return { ok: false, error: "The end must be after the start." };
      if (end.getTime() - start.getTime() > MAX_RANGE_MS) {
        return { ok: false, error: `The range is longer than ${MAX_RANGE_DAYS} days; choose a shorter range.` };
      }
    }
    return {
      ok: true,
      params: {
        ...params,
        start_date: localInputToUtcIso(f.customStart) as string,
        ...(end ? { end_date: localInputToUtcIso(f.customEnd) as string } : {}),
      },
    };
  }

  return { ok: true, params };
}

// ---------------------------------------------------------------------------------------------- display

/** "2026-11-19T10:00:05.123456+00:00" -> "2026-11-19 10:00:05" (the server always answers in UTC). */
export function formatUtcSeconds(iso: string | null | undefined): string {
  return iso ? iso.slice(0, 19).replace("T", " ") : "—";
}

// ---------------------------------------------------------------------------------------------- persistence

export const FILTER_STORAGE_KEY = "phantom.reports.filters.v1";

export interface StoredReportState {
  filters: ReportFilters;
  applied: ReportFilters;
}

function sanitiseFilters(raw: unknown): ReportFilters | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const str = (v: unknown, fallback: string) => (typeof v === "string" ? v.slice(0, 64) : fallback);
  const period = REPORT_PERIODS.find((p) => p === r.period) ?? DEFAULT_FILTERS.period;
  const relativeUnit = RELATIVE_UNITS.find((u) => u === r.relativeUnit) ?? DEFAULT_FILTERS.relativeUnit;
  return {
    period,
    analyst: str(r.analyst, "all").trim() || "all",
    severities: Array.isArray(r.severities) ? normaliseSeverities(r.severities.filter((s): s is string => typeof s === "string")) : [],
    customStart: str(r.customStart, ""),
    customEnd: str(r.customEnd, ""),
    relativeValue: str(r.relativeValue, DEFAULT_FILTERS.relativeValue),
    relativeUnit,
  };
}

/** Read the saved filters defensively: anything malformed falls back to the defaults. */
export function parseStoredState(raw: string | null | undefined): StoredReportState {
  const fallback: StoredReportState = { filters: { ...DEFAULT_FILTERS }, applied: { ...DEFAULT_FILTERS } };
  if (!raw) return fallback;
  try {
    const data = JSON.parse(raw) as Record<string, unknown>;
    const filters = sanitiseFilters(data?.filters);
    const applied = sanitiseFilters(data?.applied);
    if (!filters || !applied) return fallback;
    // Never trust a stored "applied" range that no longer validates: fall back to the preset default.
    return { filters, applied: validateFilters(applied).ok ? applied : { ...DEFAULT_FILTERS, analyst: applied.analyst, severities: applied.severities } };
  } catch {
    return fallback;
  }
}

export function serialiseStoredState(state: StoredReportState): string {
  return JSON.stringify(state);
}
