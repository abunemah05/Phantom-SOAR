import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  DEFAULT_FILTERS,
  FILTER_STORAGE_KEY,
  MAX_RANGE_DAYS,
  ReportFilters,
  describeSeverities,
  isLastSelectedSeverity,
  formatUtcSeconds,
  localInputToUtcIso,
  maxRelativeValue,
  normaliseSeverities,
  parseLocalInput,
  parseRelativeValue,
  parseStoredState,
  serialiseStoredState,
  timeZoneLabel,
  toLocalInput,
  toggleSeverity,
  validateFilters,
} from "./reportRange";

const originalTz = process.env.TZ;
beforeAll(() => {
  process.env.TZ = "America/New_York"; // UTC-5 in winter, UTC-4 in summer, with DST gaps
});
afterAll(() => {
  if (originalTz === undefined) delete process.env.TZ;
  else process.env.TZ = originalTz;
});

const f = (over: Partial<ReportFilters>): ReportFilters => ({ ...DEFAULT_FILTERS, ...over });

describe("severity selection", () => {
  it("normalises to canonical order and treats all-four as no filter", () => {
    expect(normaliseSeverities(["low", "CRITICAL", "low"])).toEqual(["Critical", "Low"]);
    expect(normaliseSeverities(["Critical", "High", "Medium", "Low"])).toEqual([]);
    expect(normaliseSeverities(["bogus"])).toEqual([]);
    expect(normaliseSeverities([])).toEqual([]);
  });
  it("toggles from All, back to All and between levels", () => {
    expect(toggleSeverity([], "Low")).toEqual(["Critical", "High", "Medium"]); // untick one from "All"
    expect(toggleSeverity(["Critical"], "High")).toEqual(["Critical", "High"]);
    expect(toggleSeverity(["Critical", "High"], "Critical")).toEqual(["High"]);
    expect(toggleSeverity(["Critical", "High", "Medium"], "Low")).toEqual([]); // all four again = All
  });
  it("never turns unticking the last selected severity into All", () => {
    expect(toggleSeverity(["High"], "High")).toEqual(["High"]); // refused: the UI disables that checkbox
    expect(isLastSelectedSeverity(["High"], "High")).toBe(true);
    expect(isLastSelectedSeverity(["High"], "Low")).toBe(false);
    expect(isLastSelectedSeverity(["High", "Low"], "High")).toBe(false);
    expect(isLastSelectedSeverity([], "High")).toBe(false); // "All": unticking one leaves the other three
    expect(toggleSeverity(["High", "Low"], "High")).toEqual(["Low"]);
  });
  it("describes the filter", () => {
    expect(describeSeverities([])).toBe("All severities");
    expect(describeSeverities(undefined)).toBe("All severities");
    expect(describeSeverities(["Critical", "High"])).toBe("Critical, High");
  });
});

describe("local datetime parsing (to the second, in the browser zone)", () => {
  it("converts winter and summer local times to UTC, with seconds", () => {
    expect(localInputToUtcIso("2026-01-15T10:00:05")).toBe("2026-01-15T15:00:05Z"); // EST
    expect(localInputToUtcIso("2026-07-15T10:00:05")).toBe("2026-07-15T14:00:05Z"); // EDT
    expect(localInputToUtcIso("2026-07-15T10:00")).toBe("2026-07-15T14:00:00Z"); // seconds omitted by the browser
  });
  it("rejects malformed, impossible and nonexistent values", () => {
    for (const bad of ["", "garbage", "2026-02-30T10:00:00", "2026-13-01T10:00:00", "2026-01-01T24:00:00", "2026-01-01T10:60:00",
      "2026-01-01", "2026-01-01 10:00:00", "2026-03-08T02:30:00" /* DST gap in New York */]) {
      expect(parseLocalInput(bad), bad).toBeNull();
      expect(localInputToUtcIso(bad), bad).toBeNull();
    }
  });
  it("resolves an ambiguous clock-change time to a valid instant", () => {
    expect(localInputToUtcIso("2026-11-01T01:30:00")).not.toBeNull();
  });
  it("round-trips through toLocalInput", () => {
    const d = new Date(2026, 10, 19, 9, 8, 7);
    expect(toLocalInput(d)).toBe("2026-11-19T09:08:07");
    expect(parseLocalInput(toLocalInput(d))?.getTime()).toBe(d.getTime());
  });
  it("labels the zone with its UTC offset", () => {
    expect(timeZoneLabel(new Date("2026-01-15T12:00:00Z"))).toBe("America/New_York (UTC-05:00)");
    expect(timeZoneLabel(new Date("2026-07-15T12:00:00Z"))).toBe("America/New_York (UTC-04:00)");
  });
});

describe("relative range", () => {
  it("parses whole positive numbers only", () => {
    expect(parseRelativeValue("15")).toBe(15);
    expect(parseRelativeValue(" 7 ")).toBe(7);
    for (const bad of ["", "0", "-3", "1.5", "abc", "1e3", "1234567890"]) expect(parseRelativeValue(bad), bad).toBeNull();
  });
  it("caps every unit at the 366 day limit", () => {
    expect(maxRelativeValue("days")).toBe(MAX_RANGE_DAYS);
    expect(maxRelativeValue("hours")).toBe(366 * 24);
    expect(maxRelativeValue("minutes")).toBe(366 * 24 * 60);
    expect(maxRelativeValue("seconds")).toBe(366 * 86400);
  });
  it("builds last_n / last_unit and validates", () => {
    expect(validateFilters(f({ period: "relative", relativeValue: "90", relativeUnit: "seconds" }))).toEqual({
      ok: true,
      params: { analyst: "all", period: "relative", last_n: 90, last_unit: "seconds" },
    });
    const zero = validateFilters(f({ period: "relative", relativeValue: "0" }));
    expect(zero.ok).toBe(false);
    const huge = validateFilters(f({ period: "relative", relativeValue: "367", relativeUnit: "days" }));
    expect(huge).toMatchObject({ ok: false });
    expect(huge.ok === false && huge.error).toContain("366 days");
    expect(validateFilters(f({ period: "relative", relativeValue: "366", relativeUnit: "days" })).ok).toBe(true);
  });
});

describe("custom range", () => {
  it("sends UTC ISO bounds and keeps analyst and severity", () => {
    const r = validateFilters(f({ period: "custom", customStart: "2026-01-15T10:00:05", customEnd: "2026-01-15T11:30:00", analyst: "alice", severities: ["High", "Critical"] }));
    expect(r).toEqual({
      ok: true,
      params: { analyst: "alice", period: "custom", severity: ["Critical", "High"], start_date: "2026-01-15T15:00:05Z", end_date: "2026-01-15T16:30:00Z" },
    });
  });
  it("an empty end means 'until now' (omitted)", () => {
    const r = validateFilters(f({ period: "custom", customStart: "2026-01-15T10:00:00" }));
    expect(r.ok && r.params.end_date).toBeUndefined();
    expect(r.ok && r.params.start_date).toBe("2026-01-15T15:00:00Z");
  });
  it("explains each validation failure", () => {
    const err = (over: Partial<ReportFilters>) => {
      const r = validateFilters(f({ period: "custom", ...over }));
      return r.ok ? "" : r.error;
    };
    expect(err({})).toMatch(/start date and time/);
    expect(err({ customStart: "nonsense" })).toMatch(/start is not a valid/);
    expect(err({ customStart: "2026-01-15T10:00:00", customEnd: "2026-02-30T00:00:00" })).toMatch(/end is not a valid/);
    expect(err({ customStart: "2026-01-15T10:00:00", customEnd: "2026-01-15T10:00:00" })).toMatch(/after the start/);
    expect(err({ customStart: "2026-01-15T10:00:01", customEnd: "2026-01-15T10:00:00" })).toMatch(/after the start/);
    expect(err({ customStart: "2025-01-01T00:00:00", customEnd: "2026-06-01T00:00:00" })).toMatch(/longer than 366 days/);
    expect(err({ customStart: "1999-12-31T00:00:00", customEnd: "2000-01-02T00:00:00" })).toMatch(/before 2000/);
    expect(err({ customStart: "2026-03-08T02:30:00" })).toMatch(/start is not a valid/);
  });
  it("accepts a range of exactly one second", () => {
    expect(validateFilters(f({ period: "custom", customStart: "2026-01-15T10:00:00", customEnd: "2026-01-15T10:00:01" })).ok).toBe(true);
  });
});

describe("presets", () => {
  it("send only the period, analyst and severities", () => {
    expect(validateFilters(f({ period: "week", severities: ["Low"] }))).toEqual({
      ok: true,
      params: { analyst: "all", period: "week", severity: ["Low"] },
    });
    expect(validateFilters(DEFAULT_FILTERS)).toEqual({ ok: true, params: { analyst: "all", period: "month" } });
  });
});

describe("display and persistence", () => {
  it("formats server timestamps to the second in UTC", () => {
    expect(formatUtcSeconds("2026-11-19T10:00:05.123456+00:00")).toBe("2026-11-19 10:00:05");
    expect(formatUtcSeconds(null)).toBe("—");
  });
  it("round-trips the saved state", () => {
    const state = { filters: f({ period: "custom", customStart: "2026-01-15T10:00:05", severities: ["High"] }), applied: f({ period: "week", severities: ["High"], analyst: "bob" }) };
    expect(parseStoredState(serialiseStoredState(state))).toEqual(state);
  });
  it("falls back to defaults for missing or corrupt storage", () => {
    for (const raw of [null, undefined, "", "not json", "[]", "{}", '{"filters":1,"applied":2}']) {
      expect(parseStoredState(raw as string | null)).toEqual({ filters: DEFAULT_FILTERS, applied: DEFAULT_FILTERS });
    }
  });
  it("sanitises hostile or stale stored values", () => {
    const raw = JSON.stringify({
      filters: { period: "forever", analyst: "  ", severities: ["critical", "x", 5], customStart: 7, relativeUnit: "weeks", relativeValue: "9" },
      applied: { period: "custom", customStart: "", customEnd: "", analyst: "carol", severities: ["Low"] },
    });
    const s = parseStoredState(raw);
    expect(s.filters).toMatchObject({ period: "month", analyst: "all", severities: ["Critical"], customStart: "", relativeUnit: "minutes", relativeValue: "9" });
    // a stored applied range that no longer validates degrades to the default preset but keeps analyst/severity
    expect(s.applied).toMatchObject({ period: "month", analyst: "carol", severities: ["Low"] });
  });
  it("uses a versioned key", () => {
    expect(FILTER_STORAGE_KEY).toMatch(/\.v1$/);
  });
});
