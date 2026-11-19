"use client";

import React, { useEffect, useRef, useState } from "react";
import { AlertCircle, AlertTriangle, CheckCircle2, FileJson, Link2, Package, RefreshCw, ShieldCheck, Upload, X } from "lucide-react";
import { api } from "@/lib/api";
import { describeError } from "@/lib/errors";
import {
  DuplicateMode,
  ImportItemStatus,
  ImportSourceKind,
  MAX_PACK_BYTES,
  PlaybookImportReport,
  STATUS_LABELS,
  buildImportRequest,
  canConfirmImport,
  checkPackFile,
  checkPackUrl,
  importableCount,
  itemTitle,
  summarizeReport,
} from "@/lib/playbookImport";
import { useModalBehavior } from "@/components/Dialog";
import { useToast } from "@/components/Toast";

const STATUS_STYLE: Record<ImportItemStatus, string> = {
  importable: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  renamed: "bg-sky-500/10 text-sky-400 border-sky-500/20",
  skipped_duplicate: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  rejected: "bg-rose-500/10 text-rose-400 border-rose-500/20",
};

const SOURCES: Array<{ kind: ImportSourceKind; label: string; icon: React.ReactNode }> = [
  { kind: "file", label: "Upload a file", icon: <Upload className="h-3.5 w-3.5" /> },
  { kind: "starter", label: "Starter pack", icon: <Package className="h-3.5 w-3.5" /> },
  { kind: "url", label: "GitHub URL", icon: <Link2 className="h-3.5 w-3.5" /> },
];

interface Props {
  open: boolean;
  onClose: () => void;
  /** Called after a successful import so the page can reload its list. */
  onImported: (createdCount: number) => void;
}

export default function PlaybookImportDialog({ open, onClose, onImported }: Props) {
  const toast = useToast();
  const dialogRef = useRef<HTMLDivElement>(null);
  useModalBehavior(dialogRef, open, onClose);

  const [source, setSource] = useState<ImportSourceKind>("file");
  const [file, setFile] = useState<File | null>(null);
  const [fileText, setFileText] = useState<string>("");
  const [url, setUrl] = useState<string>("");
  const [onDuplicate, setOnDuplicate] = useState<DuplicateMode>("skip");
  const [report, setReport] = useState<PlaybookImportReport | null>(null);
  const [busy, setBusy] = useState<"preview" | "import" | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Start clean every time the dialog opens.
  useEffect(() => {
    if (open) {
      setSource("file");
      setFile(null);
      setFileText("");
      setUrl("");
      setOnDuplicate("skip");
      setReport(null);
      setError(null);
      setBusy(null);
    }
  }, [open]);

  if (!open) return null;

  const resetPreview = () => {
    setReport(null);
    setError(null);
  };

  const chooseSource = (kind: ImportSourceKind) => {
    setSource(kind);
    resetPreview();
  };

  const onFileChosen = async (event: React.ChangeEvent<HTMLInputElement>) => {
    resetPreview();
    const chosen = event.target.files?.[0] ?? null;
    setFile(chosen);
    setFileText("");
    if (!chosen) return;
    const problem = checkPackFile(chosen);
    if (problem) {
      setError(problem);
      return;
    }
    try {
      setFileText(await chosen.text());
    } catch {
      setError("The file could not be read.");
    }
  };

  const sourceProblem = (): string | null => {
    if (source === "file") return checkPackFile(file);
    if (source === "url") return checkPackUrl(url);
    return null;
  };

  const request = (expectedSha256?: string, duplicate: DuplicateMode = onDuplicate) =>
    buildImportRequest({ source, fileText, fileName: file?.name, url, onDuplicate: duplicate, expectedSha256 });

  const runPreview = async (duplicate: DuplicateMode = onDuplicate) => {
    const problem = sourceProblem();
    if (problem) {
      setError(problem);
      return;
    }
    if (source === "file" && !fileText) {
      setError("The file has not been read yet. Choose it again.");
      return;
    }
    setBusy("preview");
    setError(null);
    try {
      setReport(await api.previewPlaybookImport(request(undefined, duplicate)));
    } catch (err) {
      setReport(null);
      setError(describeError(err, "The pack could not be previewed."));
    } finally {
      setBusy(null);
    }
  };

  const changeDuplicate = (value: DuplicateMode) => {
    setOnDuplicate(value);
    if (report) void runPreview(value);
  };

  const confirm = async () => {
    if (!report || !canConfirmImport(report)) return;
    setBusy("import");
    setError(null);
    try {
      const result = await api.importPlaybooks(request(report.sha256));
      toast.success(
        `${result.created.length} playbook(s) imported as inactive HITL. Review each one, then enable it.`
      );
      onImported(result.created.length);
      onClose();
    } catch (err) {
      setError(describeError(err, "The import failed. Nothing was imported."));
    } finally {
      setBusy(null);
    }
  };

  const count = importableCount(report);

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="playbook-import-title"
        tabIndex={-1}
        className="w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
      >
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
              <FileJson className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <h2 id="playbook-import-title" className="text-base font-bold text-white tracking-wide">Import playbooks</h2>
              <p className="text-xs text-slate-400">
                Every imported playbook is created inactive and in HITL (approval) mode. You review and enable it.
              </p>
            </div>
          </div>
          <button
            type="button"
            aria-label="Close dialog"
            onClick={onClose}
            className="h-8 w-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition border border-slate-700/60"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5 space-y-4 overflow-y-auto">
          {error && (
            <div role="alert" className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-start space-x-2">
              <AlertCircle className="h-4 w-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex items-center space-x-2" role="tablist" aria-label="Pack source">
            {SOURCES.map((s) => (
              <button
                key={s.kind}
                type="button"
                role="tab"
                aria-selected={source === s.kind}
                onClick={() => chooseSource(s.kind)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-bold border transition ${
                  source === s.kind
                    ? "border-blue-500/40 bg-blue-500/10 text-blue-400"
                    : "border-slate-700 bg-slate-800 text-slate-400 hover:text-slate-200"
                }`}
              >
                {s.icon}
                <span>{s.label}</span>
              </button>
            ))}
          </div>

          {source === "file" && (
            <div>
              <label htmlFor="playbook-import-file" className="block text-xs font-semibold text-slate-300 mb-1.5">
                Playbook pack (.json, up to {MAX_PACK_BYTES / 1024} KB)
              </label>
              <input
                id="playbook-import-file"
                type="file"
                accept=".json,application/json"
                onChange={onFileChosen}
                className="block w-full text-xs text-slate-300 file:mr-3 file:px-3 file:py-1.5 file:rounded-lg file:border-0 file:bg-slate-800 file:text-slate-200 file:text-xs file:font-semibold hover:file:bg-slate-700"
              />
            </div>
          )}

          {source === "starter" && (
            <p className="text-xs text-slate-400">
              The starter pack that ships with Phantom: extra incident types written from public frameworks (NIST SP 800-61,
              CISA, CERT-SG IRM style) and mapped to Phantom&apos;s own response actions.
            </p>
          )}

          {source === "url" && (
            <div>
              <label htmlFor="playbook-import-url" className="block text-xs font-semibold text-slate-300 mb-1.5">
                Link to a .json pack on GitHub
              </label>
              <input
                id="playbook-import-url"
                type="url"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  resetPreview();
                }}
                placeholder="https://raw.githubusercontent.com/owner/repo/main/pack.json"
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                autoComplete="off"
                spellCheck={false}
              />
              <p className="text-[11px] text-slate-500 mt-1.5">
                Only https links on raw.githubusercontent.com or api.github.com. Redirects are not followed, no login or
                token is sent, so the file must be public.
              </p>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center space-x-2">
              <label htmlFor="playbook-import-dup" className="text-xs font-semibold text-slate-300">If the name already exists</label>
              <select
                id="playbook-import-dup"
                value={onDuplicate}
                onChange={(e) => changeDuplicate(e.target.value as DuplicateMode)}
                disabled={busy !== null}
                className="px-2 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-200"
              >
                <option value="skip">Skip it</option>
                <option value="rename">Import it with a new name</option>
              </select>
            </div>
            <button
              type="button"
              onClick={() => void runPreview()}
              disabled={busy !== null}
              className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-bold text-slate-200 transition disabled:opacity-50"
            >
              {busy === "preview" ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
              <span>{busy === "preview" ? "Checking..." : report ? "Check again" : "Check the pack"}</span>
            </button>
          </div>

          {report && (
            <section aria-label="Preview" className="space-y-3 border-t border-slate-800 pt-4">
              <div className={`p-3 rounded-xl border text-xs flex items-start space-x-2 ${
                report.ok && count > 0 ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-300" : "bg-rose-500/10 border-rose-500/20 text-rose-300"
              }`}>
                {report.ok && count > 0 ? <CheckCircle2 className="h-4 w-4 flex-shrink-0 mt-0.5" /> : <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5" />}
                <span>{report.ok && count === 0 ? "Nothing would be imported." : summarizeReport(report)}</span>
              </div>

              {report.pack_errors.length > 0 && (
                <ul className="text-xs text-rose-400 list-disc pl-5 space-y-0.5">
                  {report.pack_errors.map((e, i) => <li key={i}>{e}</li>)}
                </ul>
              )}

              {report.pack.name && (
                <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-[11px] text-slate-400">
                  <div><dt className="inline font-semibold text-slate-300">Pack: </dt><dd className="inline">{report.pack.name}{report.pack.version ? ` v${report.pack.version}` : ""}</dd></div>
                  {report.pack.author && <div><dt className="inline font-semibold text-slate-300">Author: </dt><dd className="inline">{report.pack.author}</dd></div>}
                  <div className="sm:col-span-2"><dt className="inline font-semibold text-slate-300">License: </dt><dd className="inline">{report.pack.license}</dd></div>
                  <div className="sm:col-span-2 break-all"><dt className="inline font-semibold text-slate-300">SHA-256: </dt><dd className="inline font-mono">{report.sha256}</dd></div>
                </dl>
              )}

              <ul className="space-y-2">
                {report.items.map((item) => (
                  <li key={item.index} className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-sm font-semibold text-slate-100 break-words">{itemTitle(item)}</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border flex-shrink-0 ${STATUS_STYLE[item.status]}`}>
                        {STATUS_LABELS[item.status]}
                      </span>
                    </div>
                    {item.steps.length > 0 && (
                      <p className="text-[11px] text-slate-500 mt-1 font-mono break-words">{item.steps.join(" > ")}</p>
                    )}
                    {item.errors.length > 0 && (
                      <ul className="mt-1.5 text-[11px] text-rose-400 list-disc pl-5 space-y-0.5">
                        {item.errors.map((e, i) => <li key={i}>{e}</li>)}
                      </ul>
                    )}
                    {item.warnings.length > 0 && (
                      <ul className="mt-1.5 text-[11px] text-amber-400 list-disc pl-5 space-y-0.5">
                        {item.warnings.map((w, i) => <li key={i}>{w}</li>)}
                      </ul>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>

        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between gap-3">
          <span className="text-[11px] text-slate-500">
            {report && canConfirmImport(report)
              ? "Nothing is written until you confirm."
              : "Check the pack first; you will see exactly what would be imported."}
          </span>
          <div className="flex items-center space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void confirm()}
              disabled={busy !== null || !canConfirmImport(report)}
              className="flex items-center space-x-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {busy === "import" ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
              <span>{busy === "import" ? "Importing..." : count > 0 ? `Import ${count} playbook${count === 1 ? "" : "s"}` : "Import"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
