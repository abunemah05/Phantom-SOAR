// Response action catalog as served by GET /api/playbooks/actions (backend/engine/actions.py).
// FALLBACK_ACTIONS is only used when that endpoint cannot be reached, so the builder stays usable.

export type ActionImpact = "low" | "medium" | "high";
export type ActionTargetType = "host" | "ip" | "user" | "file" | "process" | "none";

export interface ActionSpec {
  name: string;
  connector: "edr" | "firewall" | "iam" | "itsm" | string;
  target_type: ActionTargetType | string;
  impact: ActionImpact | string;
  reversible?: boolean;
  description?: string;
  params?: Record<string, { type?: string; description?: string; enum?: string[]; minimum?: number; maximum?: number }>;
}

export interface ActionCatalog {
  actions: ActionSpec[];
  /** step name -> "gate" | "enrichment" | "report" */
  pseudo_steps: Record<string, string>;
}

export const FALLBACK_ACTIONS: ActionCatalog = {
  actions: [
    { name: "isolate_endpoint", connector: "edr", target_type: "host", impact: "high", params: { agent_id: { type: "string" } } },
    { name: "unisolate_endpoint", connector: "edr", target_type: "host", impact: "low", params: { agent_id: { type: "string" } } },
    { name: "terminate_process", connector: "edr", target_type: "process", impact: "medium", params: { agent_id: { type: "string" }, pid: { type: "integer" } } },
    { name: "quarantine_file", connector: "edr", target_type: "file", impact: "medium", params: { agent_id: { type: "string" }, file_hash: { type: "string" } } },
    { name: "block_ip", connector: "firewall", target_type: "ip", impact: "medium", params: { agent_id: { type: "string" }, duration_hours: { type: "integer" }, direction: { type: "string", enum: ["inbound", "outbound", "both"] } } },
    { name: "unblock_ip", connector: "firewall", target_type: "ip", impact: "low", params: { agent_id: { type: "string" } } },
    { name: "apply_rate_limit", connector: "firewall", target_type: "ip", impact: "low", params: { agent_id: { type: "string" }, rate: { type: "string" } } },
    { name: "disable_account", connector: "iam", target_type: "user", impact: "high", params: { reason: { type: "string" } } },
    { name: "revoke_user_sessions", connector: "iam", target_type: "user", impact: "medium", params: {} },
    { name: "force_password_reset", connector: "iam", target_type: "user", impact: "medium", params: {} },
    { name: "create_ticket", connector: "itsm", target_type: "none", impact: "low", params: { summary: { type: "string" }, description: { type: "string" }, priority: { type: "string" } } },
    { name: "send_notification", connector: "itsm", target_type: "none", impact: "low", params: { title: { type: "string" }, message: { type: "string" }, level: { type: "string" } } },
  ],
  pseudo_steps: {
    await_analyst_approval: "gate",
    enrich_ioc: "enrichment",
    generate_report: "report",
  },
};

export const PSEUDO_STEP_LABELS: Record<string, string> = {
  gate: "Pause until an analyst approves",
  enrichment: "No-op: enrichment already ran at ingest",
  report: "Generate the PDF incident report",
};

/** Parse "key: value, key2: value2" (or a JSON object) into a params object with basic type coercion. */
export function parseParams(text: string): { params: Record<string, unknown>; error: string | null } {
  const trimmed = text.trim();
  if (!trimmed) return { params: {}, error: null };
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return { params: parsed, error: null };
      return { params: {}, error: "Params JSON must be an object." };
    } catch (e: any) {
      return { params: {}, error: `Invalid params JSON: ${e.message}` };
    }
  }
  const params: Record<string, unknown> = {};
  for (const part of trimmed.split(",")) {
    if (!part.trim()) continue;
    const idx = part.indexOf(":");
    if (idx <= 0) return { params: {}, error: `Expected "key: value" but got "${part.trim()}".` };
    const key = part.slice(0, idx).trim();
    const raw = part.slice(idx + 1).trim().replace(/^["']|["']$/g, "");
    if (raw === "true" || raw === "false") params[key] = raw === "true";
    else if (raw !== "" && !Number.isNaN(Number(raw))) params[key] = Number(raw);
    else params[key] = raw;
  }
  return { params, error: null };
}

export function formatParams(params: unknown): string {
  if (!params || typeof params !== "object") return "";
  return Object.entries(params as Record<string, unknown>)
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(", ");
}
