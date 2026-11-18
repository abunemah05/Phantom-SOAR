import { describe, expect, it } from "vitest";
import { categoryMeta, fieldLabel, inferFieldKind, isIpOrCidr, normalizeBool, sortedCategories, validateConfigValue } from "./configRules";

describe("validateConfigValue", () => {
  it("accepts empty values (use default)", () => {
    expect(validateConfigValue("vt_requests_per_minute", "")).toBeNull();
  });
  it("enforces numeric ranges and integer-ness", () => {
    expect(validateConfigValue("agent_min_confidence", "0.8")).toBeNull();
    expect(validateConfigValue("agent_min_confidence", "1.5")).not.toBeNull();
    expect(validateConfigValue("vt_requests_per_minute", "4.5")).not.toBeNull();
    expect(validateConfigValue("vt_requests_per_minute", "abc")).not.toBeNull();
    expect(validateConfigValue("tip_malicious_threshold", "0")).not.toBeNull();
  });
  it("validates booleans, enums, URLs, IPs and model slugs", () => {
    expect(validateConfigValue("ai_enabled", "yes")).toBeNull();
    expect(validateConfigValue("ai_enabled", "maybe")).not.toBeNull();
    expect(validateConfigValue("agent_autonomy", "policy")).toBeNull();
    expect(validateConfigValue("agent_autonomy", "yolo")).not.toBeNull();
    expect(validateConfigValue("siem_manager_url", "https://wazuh:55000")).toBeNull();
    expect(validateConfigValue("siem_manager_url", "ftp://x")).not.toBeNull();
    expect(validateConfigValue("protected_ips", "10.0.0.1, 192.168.0.0/24")).toBeNull();
    expect(validateConfigValue("protected_ips", "10.0.0.256")).not.toBeNull();
    expect(validateConfigValue("openrouter_model", "vendor/model")).toBeNull();
    expect(validateConfigValue("openrouter_model", "bad model")).not.toBeNull();
  });
});

describe("helpers", () => {
  it("normalises booleans", () => {
    expect(normalizeBool(" ON ")).toBe("true");
    expect(normalizeBool("0")).toBe("false");
    expect(normalizeBool("x")).toBeNull();
  });
  it("recognises IPs and CIDRs", () => {
    expect(isIpOrCidr("10.0.0.0/8")).toBe(true);
    expect(isIpOrCidr("10.0.0.0/33")).toBe(false);
    expect(isIpOrCidr("::1")).toBe(true);
  });
  it("renders unknown keys and categories generically", () => {
    expect(fieldLabel("wazuh_ar_block_command")).toBe("AR command: block IP");
    expect(fieldLabel("some_new_ai_key")).toBe("Some new AI key");
    expect(categoryMeta("BRAND_NEW").title).toBe("Brand new");
    expect(sortedCategories(["ZZZ", "AI", "TIP"])).toEqual(["TIP", "AI", "ZZZ"]);
  });
  it("infers control kinds from the entry", () => {
    const secret = { value: "", is_secret: true, is_set: true, preview: "••", updated_at: null };
    const plain = { value: "true", is_secret: false, is_set: true, preview: null, updated_at: null };
    expect(inferFieldKind("anything", secret)).toBe("secret");
    expect(inferFieldKind("new_switch", plain)).toBe("bool");
    expect(inferFieldKind("ai_max_alerts_per_minute", { ...plain, value: "10" })).toBe("number");
    expect(inferFieldKind("new_agent_ids", { ...plain, value: "" })).toBe("list");
  });
});
