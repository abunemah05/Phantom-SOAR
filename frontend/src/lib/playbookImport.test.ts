import { describe, expect, it } from "vitest";
import {
  MAX_PACK_BYTES,
  PlaybookImportReport,
  buildImportRequest,
  canConfirmImport,
  checkPackFile,
  checkPackUrl,
  importableCount,
  itemTitle,
  summarizeReport,
} from "./playbookImport";
import { canAdminister } from "./roles";

function report(overrides: Partial<PlaybookImportReport> = {}): PlaybookImportReport {
  return {
    ok: true,
    sha256: "a".repeat(64),
    size_bytes: 100,
    on_duplicate: "skip",
    source: { kind: "file", filename: "p.json" },
    pack: { name: "Pack", license: "CC0-1.0" },
    pack_errors: [],
    items: [],
    counts: { total: 4, importable: 1, renamed: 1, skipped_duplicate: 1, rejected: 1 },
    forced: { inactive: true, execution_mode: "HITL" },
    ...overrides,
  };
}

describe("checkPackFile", () => {
  it("accepts a small .json file", () => {
    expect(checkPackFile({ name: "pack.JSON", size: 1000 })).toBeNull();
  });
  it("rejects missing, wrong-type, empty and oversize files", () => {
    expect(checkPackFile(null)).toMatch(/Choose/);
    expect(checkPackFile({ name: "pack.yaml", size: 10 })).toMatch(/\.json/);
    expect(checkPackFile({ name: "pack.json", size: 0 })).toMatch(/empty/);
    expect(checkPackFile({ name: "pack.json", size: MAX_PACK_BYTES + 1 })).toMatch(/limit/);
    expect(checkPackFile({ name: "pack.json", size: MAX_PACK_BYTES })).toBeNull();
  });
});

describe("checkPackUrl", () => {
  it("accepts raw.githubusercontent.com and api.github.com https json URLs", () => {
    expect(checkPackUrl("https://raw.githubusercontent.com/o/r/main/pack.json")).toBeNull();
    expect(checkPackUrl("https://api.github.com/repos/o/r/contents/pack.json?ref=main")).toBeNull();
  });
  it("refuses everything else", () => {
    expect(checkPackUrl("")).toMatch(/Enter/);
    expect(checkPackUrl("not a url")).toMatch(/valid/);
    expect(checkPackUrl("http://raw.githubusercontent.com/o/r/main/pack.json")).toMatch(/https/);
    expect(checkPackUrl("https://github.com/o/r/blob/main/pack.json")).toMatch(/Only/);
    expect(checkPackUrl("https://raw.githubusercontent.com.evil.example/o/r/main/pack.json")).toMatch(/Only/);
    expect(checkPackUrl("https://user:pw@raw.githubusercontent.com/o/r/main/pack.json")).toMatch(/credentials/);
    expect(checkPackUrl("https://raw.githubusercontent.com/o/r/main/pack.txt")).toMatch(/\.json/);
  });
});

describe("report helpers", () => {
  it("counts what would be imported", () => {
    expect(importableCount(report())).toBe(2);
    expect(importableCount(null)).toBe(0);
  });
  it("only allows confirming a valid report that would create something", () => {
    expect(canConfirmImport(report())).toBe(true);
    expect(canConfirmImport(null)).toBe(false);
    expect(canConfirmImport(report({ ok: false }))).toBe(false);
    expect(canConfirmImport(report({ sha256: "" }))).toBe(false);
    expect(canConfirmImport(report({ counts: { total: 2, importable: 0, renamed: 0, skipped_duplicate: 1, rejected: 1 } }))).toBe(false);
  });
  it("summarises in one sentence", () => {
    expect(summarizeReport(report())).toBe("2 of 4 playbook(s) can be imported, 1 renamed, 1 skipped as duplicates, 1 rejected.");
    expect(summarizeReport(report({ ok: false }))).toBe("This pack cannot be imported.");
  });
  it("titles an item by final name, then name, then position", () => {
    expect(itemTitle({ index: 3, name: "A", final_name: "A (imported)" })).toBe("A (imported)");
    expect(itemTitle({ index: 3, name: "A", final_name: null })).toBe("A");
    expect(itemTitle({ index: 3, name: null, final_name: null })).toBe("Playbook #3");
  });
});

describe("buildImportRequest", () => {
  it("sends file content and name only for a file source", () => {
    expect(buildImportRequest({ source: "file", fileText: "{}", fileName: "p.json", url: "https://x", onDuplicate: "rename" })).toEqual({
      source: "file", content: "{}", filename: "p.json", on_duplicate: "rename",
    });
  });
  it("sends a trimmed url only for a url source and the sha256 when confirming", () => {
    expect(buildImportRequest({ source: "url", url: "  https://raw.githubusercontent.com/o/r/main/p.json ", fileText: "{}", onDuplicate: "skip", expectedSha256: "b".repeat(64) })).toEqual({
      source: "url", url: "https://raw.githubusercontent.com/o/r/main/p.json", on_duplicate: "skip", expected_sha256: "b".repeat(64),
    });
  });
  it("sends no content or url for the starter pack", () => {
    expect(buildImportRequest({ source: "starter", fileText: "{}", url: "x", onDuplicate: "skip" })).toEqual({ source: "starter", on_duplicate: "skip" });
  });
});

describe("who sees the Import button", () => {
  it("is shown to administrators only (same rule as the backend)", () => {
    expect(canAdminister({ role: "Admin" })).toBe(true);
    ["Security Engineer", "SOC Analyst", "SOC Auditor (Read-Only)"].forEach((role) => expect(canAdminister({ role })).toBe(false));
  });
});
