import { User } from "./types";

// Mirrors the explicit role sets in backend/dependencies.py. The backend is the
// authority; these only decide what the UI offers. Matching is exact after
// whitespace/case normalisation, never substring based.

export const ROLE_ADMIN = "Admin";
export const ROLE_SECURITY_ENGINEER = "Security Engineer";
export const ROLE_SOC_ANALYST = "SOC Analyst";
export const ROLE_AUDITOR = "SOC Auditor (Read-Only)";

/** Roles an administrator can assign to a human operator. */
export const ASSIGNABLE_ROLES: Array<{ role: string; description: string }> = [
  { role: ROLE_SOC_ANALYST, description: "Triage alerts and approve or dismiss containment" },
  { role: ROLE_SECURITY_ENGINEER, description: "Analyst rights plus playbook authoring and integration settings" },
  { role: ROLE_AUDITOR, description: "Read-only access to cases and reports" },
  { role: ROLE_ADMIN, description: "Full administration: accounts, configuration, HOTL" },
];

export function normalizeRole(role?: string | null): string {
  return (role || "").split(/\s+/).filter(Boolean).join(" ").toLowerCase();
}

function roleSet(...names: string[]): Set<string> {
  return new Set(names.map(normalizeRole));
}

const ADMIN_ROLES = roleSet(
  ROLE_ADMIN,
  "Administrator",
  "System Administrator",
  "Sys Admin",
  "Lead SOC Architect / Admin",
  "SOC Lead / Admin",
  "SOC Lead / Incident Commander",
);

const SECURITY_ENGINEER_ROLES = roleSet(ROLE_SECURITY_ENGINEER, "Sec Eng");

const ANALYST_ROLES = roleSet(
  ROLE_SOC_ANALYST,
  "SOC Analyst Tier 1",
  "SOC Analyst Tier 2",
  "Tier 1 Analyst",
  "Tier 2 Analyst",
  "Tier 1 Analyst (Triage & Monitoring)",
  "Tier 2 Analyst (Senior Responder)",
  "Tier 2 Analyst (Senior)",
  "Threat Hunter / Intel Specialist",
  "SOC L1",
  "SOC L2",
);

const READ_ONLY_ROLES = roleSet(ROLE_AUDITOR, "Auditor", "Read-Only");

export type RoleLevel = "admin" | "security_engineer" | "analyst" | "read_only" | "service" | "unknown";

export function isAdmin(user?: Pick<User, "role"> | null): boolean {
  return Boolean(user && ADMIN_ROLES.has(normalizeRole(user.role)));
}

export function isSecEngOrAdmin(user?: Pick<User, "role"> | null): boolean {
  if (!user) return false;
  const r = normalizeRole(user.role);
  return ADMIN_ROLES.has(r) || SECURITY_ENGINEER_ROLES.has(r);
}

export function isReadOnly(user?: Pick<User, "role"> | null): boolean {
  return Boolean(user && READ_ONLY_ROLES.has(normalizeRole(user.role)));
}

export function roleLevel(user?: Pick<User, "role" | "is_service_account"> | null): RoleLevel {
  if (!user) return "unknown";
  if (user.is_service_account) return "service";
  const r = normalizeRole(user.role);
  if (ADMIN_ROLES.has(r)) return "admin";
  if (SECURITY_ENGINEER_ROLES.has(r)) return "security_engineer";
  if (ANALYST_ROLES.has(r)) return "analyst";
  if (READ_ONLY_ROLES.has(r)) return "read_only";
  return "unknown";
}

export function needsPasswordChange(user?: User | null): boolean {
  return Boolean(user && (user.must_change_password || user.compromised_reset_required));
}

export function needsMfaEnrollment(user?: User | null): boolean {
  return Boolean(user && user.mfa_enrollment_required && !user.mfa_enabled);
}

/**
 * Operators who may act on alerts: analysts, security engineers and administrators
 * (backend require_analyst_or_admin / require_responder). Auditors, service and unknown roles may not.
 */
export function canRespond(user?: Pick<User, "role" | "is_service_account"> | null): boolean {
  const level = roleLevel(user);
  return level === "admin" || level === "security_engineer" || level === "analyst";
}

/** Approve, reject or trigger AI proposals: analyst or above (backend require_responder); read-only auditors only read. */
export function canDecideProposals(user?: Pick<User, "role" | "is_service_account"> | null): boolean {
  return canRespond(user);
}

/** Create, edit, toggle and delete playbooks (backend require_sec_eng_or_admin). */
export function canEditPlaybooks(user?: Pick<User, "role"> | null): boolean {
  return isSecEngOrAdmin(user);
}

/** Read the integration settings page (backend require_config_viewer). */
export function canViewConfig(user?: Pick<User, "role"> | null): boolean {
  return isSecEngOrAdmin(user);
}

/** Change settings, run connection tests, toggle HOTL, purge cases, manage accounts (backend require_admin). */
export function canAdminister(user?: Pick<User, "role"> | null): boolean {
  return isAdmin(user);
}

/** Short label for the sidebar: what the signed-in role can do. */
export function accessLabel(user?: Pick<User, "role" | "is_service_account"> | null): string {
  switch (roleLevel(user)) {
    case "admin":
      return "Admin";
    case "security_engineer":
      return "Sec Eng";
    case "analyst":
      return "Analyst";
    case "read_only":
      return "Read-only";
    case "service":
      return "Service";
    default:
      return "Unknown role";
  }
}
