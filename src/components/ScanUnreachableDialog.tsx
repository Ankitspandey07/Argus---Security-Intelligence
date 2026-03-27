"use client";

import { AlertTriangle, X } from "lucide-react";

export default function ScanUnreachableDialog({
  title,
  detail,
  target,
  onClose,
}: {
  title: string;
  detail: string;
  target: string;
  onClose: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/75"
      role="alertdialog"
      aria-modal
      aria-labelledby="scan-unreachable-title"
      aria-describedby="scan-unreachable-desc"
    >
      <div className="bg-surface border border-danger/30 rounded-xl max-w-md w-full shadow-2xl overflow-hidden">
        <div className="flex items-start gap-3 px-4 py-3 border-b border-border bg-danger/5">
          <div className="shrink-0 mt-0.5 w-9 h-9 rounded-lg bg-danger/15 flex items-center justify-center">
            <AlertTriangle className="w-5 h-5 text-danger" aria-hidden />
          </div>
          <div className="min-w-0 flex-1 pt-0.5">
            <h2 id="scan-unreachable-title" className="text-sm font-semibold text-white">
              {title}
            </h2>
            <p className="text-[11px] text-text-muted mt-1 font-mono break-all">{target}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="shrink-0 p-2 rounded-lg text-text-dim hover:text-white hover:bg-bg transition-colors"
            aria-label="Dismiss"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="px-4 py-3">
          <p id="scan-unreachable-desc" className="text-sm text-text-muted leading-relaxed">
            {detail}
          </p>
          <p className="text-xs text-text-dim mt-3">
            The scan was stopped so other checks (SSL, ports, etc.) are not run against an unreachable target.
          </p>
        </div>
        <div className="px-4 py-3 border-t border-border bg-bg/40 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm font-medium bg-accent text-white hover:bg-accent/90 transition-colors"
          >
            OK
          </button>
        </div>
      </div>
    </div>
  );
}
