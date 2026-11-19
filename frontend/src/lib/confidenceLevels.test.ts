import { describe, expect, it } from "vitest";
import {
  CONFIDENCE_HELP, DEFAULT_CONFIDENCE, confidenceLabel, confidenceOptions, customConfidenceLabel, matchConfidenceLevel, percentText,
} from "./confidenceLevels";
import { FIELD_META, inferFieldKind, validateConfigValue } from "./configRules";

describe("confidenceOptions", () => {
  const options = confidenceOptions();

  it("lists named levels from highest to lowest with the percentage in the label", () => {
    expect(options[0].label).toBe("Near certain (99%)");
    expect(options.map((o) => o.label)).toContain("Very high (95%)");
    expect(options.map((o) => o.label)).toContain("High (90%)");
    expect(options.map((o) => o.label)).toContain("Moderate (80%)");
    const values = options.map((o) => Number(o.value));
    expect([...values].sort((a, b) => b - a)).toEqual(values);
    expect(new Set(options.map((o) => o.value)).size).toBe(options.length);
    expect(Math.min(...values)).toBeGreaterThanOrEqual(0.5);
    expect(Math.max(...values)).toBeLessThanOrEqual(0.99);
  });

  it("marks exactly one level as the default, and it is the backend default", () => {
    const defaults = options.filter((o) => o.label.startsWith("Default"));
    expect(defaults).toHaveLength(1);
    expect(defaults[0].value).toBe(DEFAULT_CONFIDENCE);
    expect(defaults[0].label).toBe("Default (85%)");
    expect(DEFAULT_CONFIDENCE).toBe("0.85");
  });

  it("uses canonical values the backend stores unchanged (str(float)) and every one passes validation", () => {
    for (const o of options) {
      expect(String(Number(o.value))).toBe(o.value);
      expect(validateConfigValue("agent_min_confidence", o.value)).toBeNull();
      expect(o.help).toBeTruthy();
    }
  });

  it("agrees between the label percentage and the numeric value", () => {
    for (const o of options) expect(o.label).toContain(`(${Math.round(Number(o.value) * 100)}%)`);
  });
});

describe("matching and custom values", () => {
  it("matches a stored value to its option numerically, whatever the spelling", () => {
    expect(matchConfidenceLevel("0.85")).toBe("0.85");
    expect(matchConfidenceLevel("0.90")).toBe("0.9");
    expect(matchConfidenceLevel(" 0.9 ")).toBe("0.9");
    expect(matchConfidenceLevel("0.950")).toBe("0.95");
    expect(matchConfidenceLevel(0.8)).toBe("0.8");
  });

  it("treats an empty value as the default level", () => {
    expect(matchConfidenceLevel("")).toBe(DEFAULT_CONFIDENCE);
    expect(matchConfidenceLevel("   ")).toBe(DEFAULT_CONFIDENCE);
    expect(matchConfidenceLevel(undefined)).toBeNull();
  });

  it("returns null for values that are not listed", () => {
    expect(matchConfidenceLevel("0.87")).toBeNull();
    expect(matchConfidenceLevel("1")).toBeNull();
    expect(matchConfidenceLevel("0")).toBeNull();
    expect(matchConfidenceLevel("abc")).toBeNull();
    expect(matchConfidenceLevel("NaN")).toBeNull();
  });

  it("labels unlisted values as Custom without throwing", () => {
    expect(customConfidenceLabel("0.87")).toBe("Custom (87%)");
    expect(customConfidenceLabel("0.874")).toBe("Custom (87.4%)");
    expect(customConfidenceLabel("1")).toBe("Custom (100%)");
    expect(customConfidenceLabel("0.3")).toBe("Custom (30%)");
    expect(customConfidenceLabel("garbage")).toBe("Custom (garbage)");
    expect(customConfidenceLabel("0.85")).toBeNull();
    expect(customConfidenceLabel("")).toBeNull();
    expect(customConfidenceLabel(null)).toBeNull();
  });

  it("gives every stored value a display label", () => {
    expect(confidenceLabel("0.9")).toBe("High (90%)");
    expect(confidenceLabel("0.90")).toBe("High (90%)");
    expect(confidenceLabel("0.87")).toBe("Custom (87%)");
    expect(confidenceLabel("")).toBe("Default (85%)");
  });

  it("round trips: every option value is matched back to itself and re-labelled identically", () => {
    for (const o of confidenceOptions()) {
      expect(matchConfidenceLevel(o.value)).toBe(o.value);
      expect(customConfidenceLabel(o.value)).toBeNull();
      expect(confidenceLabel(o.value)).toBe(o.label);
    }
  });

  it("formats whole percentages", () => {
    expect(percentText(0.85)).toBe("85%");
    expect(percentText(0.995)).toBe("100%");
  });
});

describe("agent_min_confidence field wiring", () => {
  it("is a select, not a typed field, and carries a help line", () => {
    expect(inferFieldKind("agent_min_confidence", undefined)).toBe("select");
    const meta = FIELD_META.agent_min_confidence;
    expect(meta.kind).toBe("select");
    expect(meta.options).toEqual(confidenceOptions());
    expect(meta.help).toContain(CONFIDENCE_HELP);
    expect(meta.canonicalValue?.("0.90")).toBe("0.9");
    expect(meta.customLabel?.("0.87")).toBe("Custom (87%)");
  });

  it("still rejects out-of-range or non-numeric values if one is ever sent", () => {
    for (const bad of ["1.5", "-0.1", "abc", "NaN"]) expect(validateConfigValue("agent_min_confidence", bad)).not.toBeNull();
  });
});
