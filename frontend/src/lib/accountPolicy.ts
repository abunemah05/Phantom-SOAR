import { ASSIGNABLE_ROLES, isAdmin, normalizeRole } from "./roles";
import { AccountActionKey, AccountActionState, StepUpConfirmation, User } from "./types";

// What the console offers on an account row. The BACKEND decides (backend/rbac.py): GET /api/users returns
// `account_actions` for every row and the server enforces the same rules on every request. These helpers only
// read that answer and phrase it; they never grant anything the server would refuse.

export interface ActionView {
  allowed: boolean;
  /** Short explanation of a refusal (or of why a confirmation is needed). Empty when there is nothing to say. */
  reason: string;
  /** The administrator must re-enter their own password (and an MFA code when they use MFA). */
  stepUp: boolean;
}

/** An older backend sends no `account_actions`: offer the action and let the server decide. */
export function actionState(user: Pick<User, "account_actions">, key: AccountActionKey): ActionView {
  const state: AccountActionState | undefined = user.account_actions?.[key];
  if (!state) return { allowed: true, reason: "", stepUp: false };
  return { allowed: state.allowed !== false, reason: state.reason ?? "", stepUp: Boolean(state.step_up) };
}

/**
 * A role change needs a confirmation when the target is an administrator (demotion) or the new role is
 * Admin (promotion). The server's per-row answer is probed with a non-admin role, so promotion is added here.
 */
export function roleChangeNeedsStepUp(target: Pick<User, "role" | "is_service_account">, newRole: string): boolean {
  if (target.is_service_account) return false;
  return isAdmin(target) || isAdmin({ role: newRole });
}

/** Roles that can be assigned to a person. Service accounts have a fixed role, so nothing is offered for them. */
export function roleOptionsFor(target: Pick<User, "is_service_account">): Array<{ role: string; description: string }> {
  return target.is_service_account ? [] : ASSIGNABLE_ROLES;
}

/**
 * What the "Change role" dialog starts with. `current` is the stored role when it is one of the assignable roles
 * (matched ignoring case and spacing), otherwise "": a legacy or unknown stored role ("Sys Admin", "SOC Lead / Admin",
 * "Administrator") is NOT one of the options, so nothing is preselected and the operator has to choose a role
 * deliberately. `stored` is the role exactly as stored, shown in the dialog.
 */
export function initialRoleSelection(target: Pick<User, "role" | "is_service_account">): { current: string; selected: string; stored: string } {
  const stored = (target.role ?? "").trim();
  const current = roleOptionsFor(target).find((r) => normalizeRole(r.role) === normalizeRole(stored))?.role ?? "";
  return { current, selected: current, stored };
}

/** The "Change role" button is enabled only for a deliberately chosen role that differs from the current one. */
export function canSubmitRoleChange(selected: string, current: string): boolean {
  return selected !== "" && selected !== current;
}

/**
 * One short line under an account explaining why some actions are locked (self, bootstrap, last administrator,
 * service account). Empty when nothing is locked.
 */
export function lockNote(user: Pick<User, "account_actions" | "is_service_account" | "is_bootstrap_admin">, isSelf: boolean): string {
  if (user.is_service_account) {
    return "Agent account: fixed role, never an administrator, cannot manage accounts. Manage its key and status only.";
  }
  if (isSelf) return "Your own role, status and password cannot be changed here. Ask another administrator.";
  if (user.is_bootstrap_admin) return "Bootstrap administrator: always an active administrator.";
  for (const key of ["change_role", "set_active", "delete"] as AccountActionKey[]) {
    const view = actionState(user, key);
    if (!view.allowed && view.reason) return view.reason;
  }
  return "";
}

/** Client-side check before the confirmation is sent; the server verifies the real values. Returns an error text or null. */
export function validateStepUpInput(password: string, mfaCode: string, needsMfa: boolean): string | null {
  if (!password) return "Enter your own password to confirm.";
  if (needsMfa && !/^\d{6,8}$/.test(mfaCode.trim())) return "Enter the current 6-digit code from your authenticator app.";
  return null;
}

export function buildConfirmation(password: string, mfaCode: string, needsMfa: boolean): StepUpConfirmation {
  const confirmation: StepUpConfirmation = { current_password: password };
  if (needsMfa && mfaCode.trim()) confirmation.mfa_code = mfaCode.trim();
  return confirmation;
}
