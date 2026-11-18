import { describe, expect, it } from "vitest";
import { alertStatusMeta, autonomyMeta, confidenceText, executionModeMeta, nvdCveStatusMeta, nvdLookupMessage, providerStatusMeta, retryText } from "./status";

describe("retryText", () => {
  it("formats seconds and minutes", () => {
    expect(retryText(45)).toBe("retry in 45s");
    expect(retryText(300)).toBe("retry in 5m");
    expect(retryText(0)).toBe("");
    expect(retryText(undefined)).toBe("");
  });
});

describe("alert statuses", () => {
  it("labels Simulated as not contained and keeps Processing distinct", () => {
    const sim = alertStatusMeta("Simulated");
    expect(sim.label.toLowerCase()).toContain("simulated");
    expect(sim.label.toLowerCase()).toContain("not contained");
    expect(alertStatusMeta("Processing").className).not.toBe(alertStatusMeta("Contained").className);
    expect(alertStatusMeta("Simulated").className).not.toBe(alertStatusMeta("Contained").className);
  });
});

describe("provider and NVD statuses", () => {
  it("shows the retry hint for rate-limited providers", () => {
    expect(providerStatusMeta("rate_limited", 30).label).toBe("Rate limited — retry in 30s");
    expect(providerStatusMeta("rate_limited").label).toBe("Rate limited");
  });
  it("gives an honest message per NVD lookup status", () => {
    expect(nvdLookupMessage("rate_limited", 40)).toContain("retry in 40s");
    expect(nvdLookupMessage("pending")).toMatch(/queued/i);
    expect(nvdLookupMessage("partial", 10)).toContain("retry in 10s");
    expect(nvdLookupMessage("no_cves")).toMatch(/no cve/i);
    expect(nvdLookupMessage("unavailable")).toMatch(/unreachable|failed/i);
    expect(nvdCveStatusMeta("rate_limited", 20).label).toBe("Rate limited — retry in 20s");
  });
});

describe("execution modes and AI helpers", () => {
  it("labels simulated actions", () => {
    expect(executionModeMeta("simulated").label).toBe("SIMULATED");
    expect(executionModeMeta("live").label).toBe("LIVE");
  });
  it("formats confidence and autonomy", () => {
    expect(confidenceText(0.857)).toBe("86%");
    expect(confidenceText(undefined)).toBe("—");
    expect(autonomyMeta("recommend_only").label.toLowerCase()).toContain("recommend");
  });
});
