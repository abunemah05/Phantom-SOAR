import { describe, expect, it } from "vitest";
import { actionState, buildConfirmation, canSubmitRoleChange, initialRoleSelection, lockNote, roleChangeNeedsStepUp, roleOptionsFor, validateStepUpInput } from "./accountPolicy";
import { ApiError, isStepUpRequired, parseErrorBody } from "./errors";
import { User } from "./types";

const base: User = { user_id: 2, username: "bob", role: "SOC Analyst" };

describe("actionState reads the server's per-row answer", () => {
  it("passes a refusal and its reason through", () => {
    const user: User = { ...base, account_actions: { change_role: { allowed: false, reason: "You cannot change your own role.", step_up: false } } };
    expect(actionState(user, "change_role")).toEqual({ allowed: false, reason: "You cannot change your own role.", stepUp: false });
  });
  it("reports a step-up", () => {
    const user: User = { ...base, account_actions: { reset_password: { allowed: true, reason: "Resetting another administrator's password.", step_up: true } } };
    expect(actionState(user, "reset_password").stepUp).toBe(true);
    expect(actionState(user, "reset_password").allowed).toBe(true);
  });
  it("offers the action when an older backend sends nothing (the server still decides)", () => {
    expect(actionState(base, "delete")).toEqual({ allowed: true, reason: "", stepUp: false });
    expect(actionState({ ...base, account_actions: {} }, "delete").allowed).toBe(true);
  });
});

describe("roleChangeNeedsStepUp", () => {
  it("is needed to demote an administrator and to promote anyone to Admin", () => {
    expect(roleChangeNeedsStepUp({ role: "Admin" }, "SOC Analyst")).toBe(true);
    expect(roleChangeNeedsStepUp({ role: "SOC Analyst" }, "Admin")).toBe(true);
    expect(roleChangeNeedsStepUp({ role: "SOC Analyst" }, "admin")).toBe(true);
  });
  it("is not needed between non-administrator roles", () => {
    expect(roleChangeNeedsStepUp({ role: "SOC Analyst" }, "Security Engineer")).toBe(false);
    expect(roleChangeNeedsStepUp({ role: "SOC Auditor (Read-Only)" }, "SOC Analyst")).toBe(false);
  });
  it("never applies to a service account", () => {
    expect(roleChangeNeedsStepUp({ role: "AI Agent", is_service_account: true }, "Admin")).toBe(false);
  });
});

describe("roleOptionsFor", () => {
  it("offers the four named roles for a person and never the AI Agent role", () => {
    const roles = roleOptionsFor({}).map((r) => r.role);
    expect(roles).toEqual(["SOC Analyst", "Security Engineer", "SOC Auditor (Read-Only)", "Admin"]);
    expect(roles).not.toContain("AI Agent");
  });
  it("offers nothing for a service account", () => {
    expect(roleOptionsFor({ is_service_account: true })).toEqual([]);
  });
});

describe("lockNote", () => {
  it("explains self, bootstrap and service accounts", () => {
    expect(lockNote(base, true)).toMatch(/own role/);
    expect(lockNote({ ...base, is_bootstrap_admin: true }, false)).toMatch(/always an active administrator/);
    expect(lockNote({ ...base, is_service_account: true }, false)).toMatch(/never an administrator/);
  });
  it("falls back to the server's reason, e.g. the last administrator", () => {
    const user: User = { ...base, role: "Admin", account_actions: { delete: { allowed: false, reason: "Cannot delete the last active administrator." } } };
    expect(lockNote(user, false)).toBe("Cannot delete the last active administrator.");
  });
  it("is empty when nothing is locked", () => {
    expect(lockNote(base, false)).toBe("");
  });
});

describe("step-up input", () => {
  it("requires the password, and a numeric code when MFA is on", () => {
    expect(validateStepUpInput("", "", false)).toMatch(/password/);
    expect(validateStepUpInput("pw", "", false)).toBeNull();
    expect(validateStepUpInput("pw", "", true)).toMatch(/code/);
    expect(validateStepUpInput("pw", "12ab56", true)).toMatch(/code/);
    expect(validateStepUpInput("pw", " 123456 ", true)).toBeNull();
  });
  it("builds the payload the API expects and omits an unused code", () => {
    expect(buildConfirmation("pw", "123456", false)).toEqual({ current_password: "pw" });
    expect(buildConfirmation("pw", " 123456 ", true)).toEqual({ current_password: "pw", mfa_code: "123456" });
  });
});

describe("policy errors from the API", () => {
  it("keeps the machine-readable code and message of {detail: {message, code}}", () => {
    const parsed = parseErrorBody(400, JSON.stringify({ detail: { message: "You cannot change your own role.", code: "self_role_change" } }));
    expect(parsed).toEqual({ message: "You cannot change your own role.", blockers: [], code: "self_role_change" });
  });
  it("recognises a missing or wrong confirmation", () => {
    expect(isStepUpRequired(new ApiError(428, "Confirm with your own password"))).toBe(true);
    expect(isStepUpRequired(new ApiError(403, "Confirmation failed", { code: "step_up_failed" }))).toBe(true);
    expect(isStepUpRequired(new ApiError(403, "Access denied"))).toBe(false);
    expect(isStepUpRequired(new Error("x"))).toBe(false);
  });
});

describe("role change dialog starting state", () => {
  const person = (role: string) => ({ role, is_service_account: false });
  it("preselects the stored role when it is one of the assignable roles", () => {
    expect(initialRoleSelection(person("Security Engineer"))).toEqual({ current: "Security Engineer", selected: "Security Engineer", stored: "Security Engineer" });
    expect(initialRoleSelection(person("  soc   analyst ")).current).toBe("SOC Analyst"); // case and spacing are ignored
  });
  it("preselects nothing for a legacy or unknown stored role, and shows it as stored", () => {
    for (const legacy of ["SOC Lead / Admin", "Sys Admin", "Administrator", "Tier 2 Analyst (Senior Responder)", ""]) {
      const start = initialRoleSelection(person(legacy));
      expect(start.current).toBe("");
      expect(start.selected).toBe("");
      expect(start.stored).toBe(legacy.trim());
      expect(canSubmitRoleChange(start.selected, start.current)).toBe(false); // no one-click demotion
    }
  });
  it("enables the button only for a deliberately chosen, different role", () => {
    expect(canSubmitRoleChange("", "")).toBe(false);
    expect(canSubmitRoleChange("SOC Analyst", "SOC Analyst")).toBe(false);
    expect(canSubmitRoleChange("SOC Analyst", "")).toBe(true); // legacy -> explicit choice
    expect(canSubmitRoleChange("Admin", "SOC Analyst")).toBe(true);
  });
  it("offers nothing for a service account", () => {
    expect(initialRoleSelection({ role: "AI Agent", is_service_account: true }).current).toBe("");
  });
});
