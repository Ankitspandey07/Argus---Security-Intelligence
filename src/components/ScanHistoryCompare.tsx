"use client";

import { useEffect, useMemo, useState } from "react";
import { History, Trash2, FolderOpen, GitCompare, X, ChevronDown } from "lucide-react";
import type { ScanResult } from "@/lib/types";
import {
  clearScanHistoryForCurrentOwner,
  loadScanHistory,
  MAX_SCAN_HISTORY,
  removeScanHistoryEntry,
  scanHistoryTtlDays,
  updateScanHistoryLabel,
  type ScanHistoryEntry,
} from "@/lib/scan-history-local";
import { useI18n } from "@/components/I18nProvider";

function snapshotScan(entry: ScanHistoryEntry): ScanResult | undefined {
  const s = entry.snapshot?.scan;
  if (s && typeof s === "object" && s !== null && typeof (s as ScanResult).score === "number") {
    return s as ScanResult;
  }
  return undefined;
}

function collectCveIds(snapshot: Record<string, unknown>): Set<string> {
  const out = new Set<string>();
  const ports = snapshot.ports as { cves?: string[] } | undefined;
  if (Array.isArray(ports?.cves)) ports.cves.forEach((c) => out.add(String(c)));
  const sa = snapshot.sourceAudit as { retireMatches?: { cves?: string[] }[] } | undefined;
  if (Array.isArray(sa?.retireMatches)) {
    for (const m of sa.retireMatches) {
      if (Array.isArray(m?.cves)) m.cves.forEach((c) => out.add(String(c)));
    }
  }
  return out;
}

function CompareModal({
  a,
  b,
  onClose,
}: {
  a: ScanHistoryEntry;
  b: ScanHistoryEntry;
  onClose: () => void;
}) {
  const { t, formatDateTime } = useI18n();
  const sa = snapshotScan(a);
  const sb = snapshotScan(b);
  const cvesA = useMemo(() => collectCveIds(a.snapshot), [a]);
  const cvesB = useMemo(() => collectCveIds(b.snapshot), [b]);
  const onlyB = useMemo(() => [...cvesB].filter((c) => !cvesA.has(c)), [cvesA, cvesB]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70" role="dialog" aria-modal>
      <div className="bg-surface border border-border rounded-xl max-w-4xl w-full max-h-[85vh] overflow-hidden flex flex-col shadow-2xl">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-accent" />
            {t("historyCompare.compareRuns")}
          </h3>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-lg text-text-dim hover:text-white hover:bg-bg transition-colors"
            aria-label={t("historyCompare.close")}
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-0 divide-y sm:divide-y-0 sm:divide-x divide-border overflow-y-auto flex-1">
          <div className="p-4 space-y-2">
            <p className="text-[10px] uppercase text-text-dim font-semibold">{t("historyCompare.runA")}</p>
            <p className="text-xs font-mono text-white">{a.label}</p>
            <p className="text-[11px] text-text-muted">{formatDateTime(a.savedAt)}</p>
            {sa ? (
              <ul className="text-xs text-text-muted space-y-1 mt-2">
                <li>
                  {t("historyCompare.score")}{" "}
                  <span className="text-white font-mono">{sa.score}</span> ({sa.grade})
                </li>
                <li>
                  {t("historyCompare.headersPass")}{" "}
                  <span className="text-white font-mono">
                    {sa.headers.filter((h) => h.status === "pass").length}/{sa.headers.length}
                  </span>
                </li>
              </ul>
            ) : (
              <p className="text-xs text-warning">{t("historyCompare.noHeaderScan")}</p>
            )}
          </div>
          <div className="p-4 space-y-2">
            <p className="text-[10px] uppercase text-text-dim font-semibold">{t("historyCompare.runB")}</p>
            <p className="text-xs font-mono text-white">{b.label}</p>
            <p className="text-[11px] text-text-muted">{formatDateTime(b.savedAt)}</p>
            {sb ? (
              <ul className="text-xs text-text-muted space-y-1 mt-2">
                <li>
                  {t("historyCompare.score")}{" "}
                  <span className="text-white font-mono">{sb.score}</span> ({sb.grade})
                </li>
                <li>
                  {t("historyCompare.headersPass")}{" "}
                  <span className="text-white font-mono">
                    {sb.headers.filter((h) => h.status === "pass").length}/{sb.headers.length}
                  </span>
                </li>
              </ul>
            ) : (
              <p className="text-xs text-warning">{t("historyCompare.noHeaderScan")}</p>
            )}
          </div>
        </div>
        <div className="p-4 border-t border-border bg-bg/40">
          <p className="text-[10px] uppercase text-text-dim font-semibold mb-2">{t("historyCompare.cvesSection")}</p>
          {onlyB.length === 0 ? (
            <p className="text-xs text-text-muted">{t("historyCompare.noCvesDiff")}</p>
          ) : (
            <p className="text-xs font-mono text-warning break-all">{onlyB.slice(0, 40).join(", ")}</p>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ScanHistoryCompare({
  onRestore,
  refreshToken,
}: {
  onRestore: (snapshot: Record<string, unknown>, target: string) => void;
  /** Bump when a new scan completes so the list reloads */
  refreshToken: number;
}) {
  const { t, formatDateTime } = useI18n();
  const [mounted, setMounted] = useState(false);
  const [entries, setEntries] = useState<ScanHistoryEntry[]>([]);
  const [pick, setPick] = useState<string[]>([]);
  const [comparePair, setComparePair] = useState<[ScanHistoryEntry, ScanHistoryEntry] | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);

  /** Avoid hydration mismatch: server and first client paint never read localStorage. */
  useEffect(() => {
    setMounted(true);
    setEntries(loadScanHistory());
  }, [refreshToken]);

  const togglePick = (id: string) => {
    setPick((prev) => {
      if (prev.includes(id)) return prev.filter((x) => x !== id);
      if (prev.length >= 2) return [prev[1], id];
      return [...prev, id];
    });
  };

  const runCompare = () => {
    if (pick.length !== 2) return;
    const a = entries.find((e) => e.id === pick[0]);
    const b = entries.find((e) => e.id === pick[1]);
    if (a && b) setComparePair([a, b]);
  };

  return (
    <div className="max-w-5xl mx-auto px-4 pb-8">
      {!mounted ? (
        <>
          <div className="flex items-center gap-2 mb-2">
            <History className="w-4 h-4 text-accent" />
            <h3 className="text-sm font-semibold text-white">{t("scanner.recentScans")}</h3>
          </div>
          <p className="text-xs text-text-muted">{t("scanner.loadingRuns")}</p>
        </>
      ) : entries.length === 0 ? (
        <>
          <div className="flex items-center gap-2 mb-2">
            <History className="w-4 h-4 text-accent" />
            <h3 className="text-sm font-semibold text-white">{t("scanner.recentScans")}</h3>
          </div>
          <p className="text-xs text-text-muted">{t("scanner.emptyHistory", { max: MAX_SCAN_HISTORY })}</p>
        </>
      ) : (
        <div className="rounded-xl border border-border bg-surface/50 overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2.5 hover:bg-surface/80 transition-colors">
            <button
              type="button"
              onClick={() => setHistoryOpen((o) => !o)}
              className="flex flex-1 items-center gap-2 min-w-0 text-left"
              aria-expanded={historyOpen}
            >
              <ChevronDown
                className={`w-4 h-4 text-text-dim shrink-0 transition-transform duration-200 ${historyOpen ? "rotate-180" : ""}`}
                aria-hidden
              />
              <History className="w-4 h-4 text-accent shrink-0" />
              <span className="text-sm font-semibold text-white">{t("scanner.recentScans")}</span>
              <span className="text-[11px] text-text-muted font-mono">({entries.length})</span>
            </button>
            <button
              type="button"
                onClick={() => {
                if (!window.confirm(t("historyCompare.clearAllConfirm"))) return;
                setEntries(clearScanHistoryForCurrentOwner());
                setPick([]);
              }}
              className="text-[10px] font-medium text-text-dim hover:text-danger border border-border rounded-md px-2 py-1 hover:border-danger/40 hover:bg-danger/5 transition-colors shrink-0"
            >
              {t("historyCompare.clearAllMine")}
            </button>
          </div>
          {historyOpen && (
            <div className="border-t border-border px-3 pb-3 pt-2 space-y-3">
              <p className="text-[10px] text-text-muted leading-relaxed max-w-3xl">
                {t("historyCompare.privacy1")}{" "}
                {t("historyCompare.privacy2", { days: scanHistoryTtlDays() })}{" "}
                {t("historyCompare.privacy3")}
              </p>
              <ul className="space-y-2 max-h-[min(55vh,28rem)] overflow-y-auto pr-1">
                {entries.map((e) => (
                  <li
                    key={e.id}
                    className="flex flex-col sm:flex-row sm:items-center gap-2 p-3 rounded-lg border border-border bg-surface/80"
                  >
                    <label className="flex items-center gap-2 shrink-0 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={pick.includes(e.id)}
                        onChange={() => togglePick(e.id)}
                        className="rounded border-border"
                      />
                      <span className="text-[10px] text-text-dim">{t("historyCompare.compareCheckbox")}</span>
                    </label>
                    <input
                      type="text"
                      value={e.label}
                      onChange={(ev) => {
                        const label = ev.target.value;
                        setEntries(updateScanHistoryLabel(e.id, label));
                      }}
                      className="flex-1 min-w-0 rounded-md border border-border bg-bg px-2 py-1 text-xs text-white font-mono"
                      aria-label="Run label"
                    />
                    <span className="text-[10px] text-text-dim shrink-0">{formatDateTime(e.savedAt)}</span>
                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        type="button"
                        onClick={() => onRestore(e.snapshot, e.target)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-accent/15 text-accent hover:bg-accent/25 border border-accent/30"
                      >
                        <FolderOpen className="w-3.5 h-3.5" />
                        {t("historyCompare.open")}
                      </button>
                      <button
                        type="button"
                        onClick={() => setEntries(removeScanHistoryEntry(e.id))}
                        className="p-1.5 rounded-md text-text-dim hover:text-danger hover:bg-danger/10"
                        aria-label={t("historyCompare.removeAria")}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={pick.length !== 2}
                  onClick={runCompare}
                  className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold bg-surface-2 border border-border text-white disabled:opacity-40 disabled:pointer-events-none hover:border-accent/40"
                >
                  <GitCompare className="w-3.5 h-3.5" />
                  {t("historyCompare.compareSelected")}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
      {comparePair && (
        <CompareModal a={comparePair[0]} b={comparePair[1]} onClose={() => setComparePair(null)} />
      )}
    </div>
  );
}
