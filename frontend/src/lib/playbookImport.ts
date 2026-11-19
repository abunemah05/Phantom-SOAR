// Playbook pack import (administrators only): request/report types and small helpers shared by the
// import dialog. The backend (backend/engine/playbook_import.py) is the authority on every rule;
// these helpers only give early feedback and plain-language labels.

export type ImportSourceKind = "file" | "url" | "starter";
export type DuplicateMode = "skip" | "rename";
export type ImportItemStatus = "importable" | "renamed" | "skipped_duplicate" | "rejected";

/** Mirrors MAX_PACK_BYTES in backend/engine/playbook_import.py. */
export const MAX_PACK_BYTES = 256 * 1024;

/** Mirrors ALLOWED_URL_HOSTS in the backend. */
export const ALLOWED_URL_HOSTS = ["raw.githubusercontent.com", "api.github.com"] as const;

export interface PlaybookImportRequest {
  source: ImportSourceKind;
  content?: string;
  filename?: string;
  url?: string;
  on_duplicate: DuplicateMode;
  expected_sha256?: string;
}

export interface PlaybookImportItem {
  index: number;
  name: string | null;
  final_name: string | null;
  target_threat?: string | null;
  requested_mode: "HOTL" | "HITL" | null;
  steps: string[];
  step_count: number;
  errors: string[];
  warnings: string[];
  status: ImportItemStatus;
}

export interface PlaybookImportReport {
  ok: boolean;
  sha256: string;
  size_bytes: number;
  on_duplicate: DuplicateMode;
  source: { kind?: ImportSourceKind; url?: string; filename?: string | null };
  pack: { name?: string; version?: string; author?: string; license?: string; source?: string; description?: string };
  pack_errors: string[];
  items: PlaybookImportItem[];
  counts: { total: number; importable: number; renamed: number; skipped_duplicate: number; rejected: number };
  forced: { inactive: boolean; execution_mode: string };
}

export interface PlaybookImportResult {
  status: string;
  message: string;
  created: Array<{ playbook_id: number; name: string; is_active: boolean; execution_mode: string }>;
  report: PlaybookImportReport;
}

/** Early check of a chosen file; returns a problem description or null when it looks usable. */
export function checkPackFile(file: { name: string; size: number } | null | undefined): string | null {
  if (!file) return "Choose a .json playbook pack first.";
  if (!/\.json$/i.test(file.name)) return "The file must be a .json playbook pack.";
  if (file.size === 0) return "The file is empty.";
  if (file.size > MAX_PACK_BYTES) return `The file is ${Math.ceil(file.size / 1024)} KB; the limit is ${MAX_PACK_BYTES / 1024} KB.`;
  return null;
}

/** Early check of a pack URL (https and an allowed GitHub host); null when it looks acceptable. */
export function checkPackUrl(value: string): string | null {
  const text = value.trim();
  if (!text) return "Enter the URL of a .json playbook pack.";
  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    return "That is not a valid URL.";
  }
  if (parsed.protocol !== "https:") return "Only https URLs are allowed.";
  if (parsed.username || parsed.password) return "URLs with embedded credentials are not allowed.";
  if (!(ALLOWED_URL_HOSTS as readonly string[]).includes(parsed.hostname.toLowerCase())) {
    return `Only ${ALLOWED_URL_HOSTS.join(" and ")} are allowed.`;
  }
  if (!/\.json$/i.test(parsed.pathname)) return "The URL must point to a .json file.";
  return null;
}

export function itemTitle(item: Pick<PlaybookImportItem, "name" | "final_name" | "index">): string {
  return item.final_name || item.name || `Playbook #${item.index}`;
}

export const STATUS_LABELS: Record<ImportItemStatus, string> = {
  importable: "Will be imported",
  renamed: "Will be imported (renamed)",
  skipped_duplicate: "Skipped (name exists)",
  rejected: "Rejected",
};

export function importableCount(report: Pick<PlaybookImportReport, "counts"> | null | undefined): number {
  return report ? report.counts.importable + report.counts.renamed : 0;
}

/** True only when the preview was valid and at least one playbook would be created. */
export function canConfirmImport(report: PlaybookImportReport | null | undefined): boolean {
  return Boolean(report && report.ok && report.sha256 && importableCount(report) > 0);
}

/** One plain sentence describing what a confirmed import would do. */
export function summarizeReport(report: PlaybookImportReport): string {
  if (!report.ok) return "This pack cannot be imported.";
  const { importable, renamed, skipped_duplicate, rejected, total } = report.counts;
  const parts = [`${importable + renamed} of ${total} playbook(s) can be imported`];
  if (renamed) parts.push(`${renamed} renamed`);
  if (skipped_duplicate) parts.push(`${skipped_duplicate} skipped as duplicates`);
  if (rejected) parts.push(`${rejected} rejected`);
  return parts.join(", ") + ".";
}

/** Build the request for the preview, or for the import when `expectedSha256` (from the preview) is given. */
export function buildImportRequest(args: {
  source: ImportSourceKind;
  fileText?: string;
  fileName?: string;
  url?: string;
  onDuplicate: DuplicateMode;
  expectedSha256?: string;
}): PlaybookImportRequest {
  const request: PlaybookImportRequest = { source: args.source, on_duplicate: args.onDuplicate };
  if (args.source === "file") {
    request.content = args.fileText ?? "";
    if (args.fileName) request.filename = args.fileName.slice(0, 300);
  } else if (args.source === "url") {
    request.url = (args.url ?? "").trim();
  }
  if (args.expectedSha256) request.expected_sha256 = args.expectedSha256;
  return request;
}
