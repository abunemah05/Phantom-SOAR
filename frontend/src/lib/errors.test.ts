import { describe, expect, it } from "vitest";
import { ApiError, describeError, errorBlockers, isMfaEnrollmentRequired, isPasswordChangeRequired, parseErrorBody, parseRetryAfter } from "./errors";

describe("parseErrorBody", () => {
  it("reads a string detail", () => {
    expect(parseErrorBody(409, JSON.stringify({ detail: "AI triage is disabled." }))).toEqual({ message: "AI triage is disabled.", blockers: [] });
  });
  it("reads {message, blockers}", () => {
    const body = JSON.stringify({ detail: { message: "Refused", blockers: ["list protected_hosts", "list protected_ips"] } });
    expect(parseErrorBody(409, body)).toEqual({ message: "Refused", blockers: ["list protected_hosts", "list protected_ips"] });
  });
  it("joins validation items without body/query prefixes", () => {
    const body = JSON.stringify({ detail: [{ loc: ["body", "username"], msg: "field required" }] });
    expect(parseErrorBody(422, body).message).toBe("username: field required");
  });
  it("never returns HTML or an empty message", () => {
    expect(parseErrorBody(502, "<html>bad gateway</html>").message).toBe("Request failed (HTTP 502).");
    expect(parseErrorBody(500, "").message).toBe("Request failed (HTTP 500).");
  });
});

describe("parseRetryAfter", () => {
  it("parses seconds and HTTP dates", () => {
    expect(parseRetryAfter("30")).toBe(30);
    expect(parseRetryAfter("0")).toBe(1);
    const now = Date.UTC(2026, 0, 1, 0, 0, 0);
    expect(parseRetryAfter("Thu, 01 Jan 2026 00:01:00 GMT", now)).toBe(60);
    expect(parseRetryAfter("nonsense")).toBeUndefined();
    expect(parseRetryAfter(null)).toBeUndefined();
  });
});

describe("describeError / errorBlockers", () => {
  it("uses the ApiError message and exposes blockers", () => {
    const err = new ApiError(409, "Refused", { blockers: ["a"] });
    expect(describeError(err)).toBe("Refused");
    expect(errorBlockers(err)).toEqual(["a"]);
  });
  it("falls back for unknown values", () => {
    expect(describeError("boom", "fallback")).toBe("fallback");
    expect(errorBlockers(new Error("x"))).toEqual([]);
  });
});

describe("restricted-session detection", () => {
  it("recognises the backend 403 messages", () => {
    expect(isPasswordChangeRequired(403, "Password change required before using the API.")).toBe(true);
    expect(isPasswordChangeRequired(401, "Password change required")).toBe(false);
    expect(isMfaEnrollmentRequired(403, "Multi-factor authentication is mandatory: enrol first.")).toBe(true);
    expect(isMfaEnrollmentRequired(403, "Forbidden")).toBe(false);
  });
});
