import { RawPayload } from "./types";

// Typed accessors for the free-form Wazuh/EDR payload stored on an alert. Alert content is attacker
// controlled: these helpers only ever return strings that React renders as text (never as HTML).

function asText(value: unknown): string | null {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number") return String(value);
  return null;
}

export function ruleDescription(payload?: RawPayload | null): string | null {
  return asText(payload?.rule?.description);
}

/** Description for list views: rule description, else the start of the log line, else the fallback. */
export function alertSummaryLine(payload: RawPayload | null | undefined, fallback: string): string {
  const description = ruleDescription(payload) || asText(payload?.full_log);
  return description || fallback;
}

export function affectedAsset(payload?: RawPayload | null): string | null {
  return asText(payload?.agent?.name) || asText(payload?.agent?.ip);
}

export function ruleLevel(payload?: RawPayload | null): string | null {
  return asText(payload?.rule?.level);
}
