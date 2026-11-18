import { describe, expect, it } from "vitest";
import { canAdminister, canDecideProposals, canEditPlaybooks, canRespond, canViewConfig, roleLevel } from "./roles";

const admin = { role: "Admin" };
const secEng = { role: "Security Engineer" };
const analyst = { role: "SOC Analyst" };
const auditor = { role: "SOC Auditor (Read-Only)" };
const service = { role: "AI Agent", is_service_account: true };

describe("role gating mirrors backend/dependencies.py", () => {
  it("only administrators administer", () => {
    expect(canAdminister(admin)).toBe(true);
    [secEng, analyst, auditor, service, null].forEach((u) => expect(canAdminister(u)).toBe(false));
  });
  it("operator roles respond and decide proposals; auditors and service accounts do not", () => {
    [admin, secEng, analyst].forEach((u) => {
      expect(canRespond(u)).toBe(true);
      expect(canDecideProposals(u)).toBe(true);
    });
    [auditor, service, null, undefined].forEach((u) => {
      expect(canRespond(u)).toBe(false);
      expect(canDecideProposals(u)).toBe(false);
    });
  });
  it("security engineers edit playbooks and view configuration", () => {
    expect(canEditPlaybooks(secEng)).toBe(true);
    expect(canViewConfig(secEng)).toBe(true);
    expect(canEditPlaybooks(analyst)).toBe(false);
    expect(canViewConfig(analyst)).toBe(false);
  });
  it("normalises role spelling and spacing", () => {
    expect(roleLevel({ role: "  soc   analyst " })).toBe("analyst");
    expect(roleLevel({ role: "mystery" })).toBe("unknown");
    expect(roleLevel(service)).toBe("service");
  });
});
