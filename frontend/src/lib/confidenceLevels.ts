// Fixed choices for the AI agent's minimum confidence (setting `agent_min_confidence`).
//
// The instructor's requirement: this trust level must not be typed on the keyboard, it is picked from a list.
// The backend still validates 0..1 strictly (backend/routers/config.py) and the policy engine still reads the
// same numeric string, so nothing downstream changes. Rationale and the research behind the default:
// docs/CONFIDENCE_LEVEL.md.
//
// Option values are the exact strings the backend stores: it normalises "0.90" to str(0.9) == "0.9", so the
// values here are written in that canonical form ("0.9", not "0.90") and a stored value is matched numerically.

import type { SelectOption } from "./configRules";

/** Same as DEFAULTS["agent_min_confidence"] in backend/integration_config.py (a test keeps them in sync). */
export const DEFAULT_CONFIDENCE = "0.85";

interface ConfidenceLevel {
  value: string;
  name: string;
  help: string;
}

// Highest first. Lower levels let the agent act on weaker evidence, so the help says what that costs.
const LEVELS: readonly ConfidenceLevel[] = [
  { value: "0.99", name: "Near certain", help: "Only the very strongest proposals can run automatically. Almost everything waits for an analyst." },
  { value: "0.95", name: "Very high", help: "Strict: only proposals the model is almost sure about can run automatically." },
  { value: "0.9", name: "High", help: "Strict: a clear majority of proposals still wait for an analyst." },
  { value: DEFAULT_CONFIDENCE, name: "Default", help: "Our default. Conservative, and it only matters once autonomy is raised above \"recommend only\"." },
  { value: "0.8", name: "Moderate", help: "More proposals qualify for automatic execution. Review the agent's past proposals first." },
  { value: "0.75", name: "Lenient", help: "Weaker proposals can run automatically. Use only for low-impact actions." },
  { value: "0.7", name: "Low", help: "Weak proposals can run without a person. Not recommended in production." },
  { value: "0.6", name: "Very low", help: "Barely better than a guess. Not recommended outside a lab." },
  { value: "0.5", name: "Minimal", help: "No real filtering by confidence. Lab use only." },
];

const EPSILON = 1e-9;

/** "0.85" -> "85%". Whole percentages only, like the rest of the console (see confidenceText in status.ts). */
export function percentText(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function parseLevel(value: string | number | null | undefined): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string" || value.trim() === "") return null;
  const number = Number(value.trim());
  return Number.isFinite(number) ? number : null;
}

/** The selectable levels, as `<option>`s: "Very high (95%)", "Default (85%)", ... */
export function confidenceOptions(): SelectOption[] {
  return LEVELS.map((level) => ({
    value: level.value,
    label: `${level.name} (${percentText(Number(level.value))})`,
    help: level.help,
  }));
}

/**
 * The canonical option value for a stored value ("0.90" -> "0.9"), or null when it is not one of the listed
 * levels. An empty value means "use the default", so it resolves to the default level.
 */
export function matchConfidenceLevel(value: string | number | null | undefined): string | null {
  if (typeof value === "string" && value.trim() === "") return DEFAULT_CONFIDENCE;
  const number = parseLevel(value);
  if (number === null) return null;
  const hit = LEVELS.find((level) => Math.abs(Number(level.value) - number) < EPSILON);
  return hit ? hit.value : null;
}

/**
 * Label for a stored value that is not in the list (set through the API or an environment variable earlier):
 * "Custom (87%)". Returns null for a listed level. Unparseable text is shown as typed, never dropped.
 */
export function customConfidenceLabel(value: string | number | null | undefined): string | null {
  if (matchConfidenceLevel(value) !== null) return null;
  const number = parseLevel(value);
  if (number === null) return typeof value === "string" && value.trim() ? `Custom (${value.trim()})` : null;
  // Whole percentages are not enough to tell 0.874 from 0.87, so show a decimal only when it matters.
  const percent = number * 100;
  const text = Math.abs(percent - Math.round(percent)) < 0.05 ? String(Math.round(percent)) : percent.toFixed(1);
  return `Custom (${text}%)`;
}

/** Display label for a stored value: the level label when listed, otherwise the "Custom (xx%)" label. */
export function confidenceLabel(value: string | number | null | undefined): string {
  const matched = matchConfidenceLevel(value);
  if (matched !== null) {
    return confidenceOptions().find((o) => o.value === matched)?.label ?? matched;
  }
  return customConfidenceLabel(value) ?? "";
}

export const CONFIDENCE_HELP =
  "How sure the AI must be before an action may run without a person. Higher is safer; the default is 85%. Applies only when autonomy is above \"recommend only\".";
