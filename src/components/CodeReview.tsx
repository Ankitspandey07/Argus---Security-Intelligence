"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import {
  Code2, Play, AlertTriangle, CheckCircle2, XCircle, Info, ChevronDown, Shield, Square,
  FileJson, FileText, FileDown, Loader2, Braces,
} from "lucide-react";
import type { CodeFinding, CodeReviewResult } from "@/lib/types";
import { jsonHeadersWithArgus } from "@/lib/argus-client-headers";

const LANGUAGES = [
  "Auto-detect",
  "JavaScript", "TypeScript", "Python", "Java", "Go", "Rust", "PHP",
  "Ruby", "C", "C++", "C#", "Kotlin", "Swift", "SQL", "Shell", "YAML", "Other",
];

/** Matches server default so the UI can show a rough ETA when Gemini is used */
const TYPICAL_AI_CAP_SECONDS = 20;

function csvEscape(s: string): string {
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function severityBarWidth(sev: string): number {
  const m: Record<string, number> = { critical: 100, high: 84, medium: 60, low: 40, info: 24 };
  return m[sev] ?? 35;
}

function semgrepSeverity(sev: string): string {
  if (sev === "critical" || sev === "high") return "ERROR";
  if (sev === "medium") return "WARNING";
  return "INFO";
}

function buildSemgrepStubYaml(result: CodeReviewResult): string {
  if (result.findings.length === 0) {
    return [
      "# Semgrep rules stub from Argus — no findings; add rules manually or re-run review.",
      "rules: []",
    ].join("\n");
  }
  const lines: string[] = [
    "# Semgrep rules stub from Argus code review — replace `pattern` (or use pattern-regex) before running.",
    "# Reference: https://semgrep.dev/docs/writing-rules/rule-syntax",
    "rules:",
  ];
  for (let i = 0; i < result.findings.length; i++) {
    const f = result.findings[i] as CodeFinding;
    lines.push(`  - id: argus-export-${i + 1}`);
    lines.push(`    message: ${JSON.stringify(`${f.title} (${f.category})`)}`);
    lines.push(`    severity: ${semgrepSeverity(f.severity)}`);
    lines.push(`    languages: [javascript, typescript, python, go, java]`);
    lines.push(
      `    pattern: "..."  # TODO line ${f.line ?? "?"} source=${f.source ?? "?"} — refine for your repo`,
    );
  }
  return lines.join("\n");
}

function gradeLetter(score: number): string {
  if (score >= 93) return "A";
  if (score >= 85) return "B";
  if (score >= 75) return "C";
  if (score >= 65) return "D";
  return "F";
}

function SecurityScoreRing({ score }: { score: number }) {
  const r = 34;
  const c = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, score)) / 100;
  const offset = c * (1 - pct);
  const stroke = score < 35 ? "#f87171" : score < 60 ? "#fbbf24" : "#4ade80";
  return (
    <div className="relative w-[88px] h-[88px] shrink-0" aria-hidden>
      <svg width="88" height="88" viewBox="0 0 88 88" className="drop-shadow-sm">
        <circle cx="44" cy="44" r={r} fill="none" stroke="rgba(148,163,184,0.22)" strokeWidth="9" />
        <circle
          cx="44"
          cy="44"
          r={r}
          fill="none"
          stroke={stroke}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          transform="rotate(-90 44 44)"
        />
        <text
          x="44"
          y="46"
          textAnchor="middle"
          dominantBaseline="middle"
          className="fill-white font-bold"
          style={{ fontSize: "22px" }}
        >
          {gradeLetter(score)}
        </text>
        <text x="44" y="64" textAnchor="middle" className="fill-slate-400" style={{ fontSize: "10px" }}>
          {score}/100
        </text>
      </svg>
    </div>
  );
}

function severityBarClass(sev: string): string {
  switch (sev) {
    case "critical":
      return "bg-danger";
    case "high":
      return "bg-orange-500";
    case "medium":
      return "bg-warning";
    case "low":
      return "bg-info";
    default:
      return "bg-text-dim";
  }
}

export default function CodeReview(props: { embedded?: boolean } = {}) {
  const { embedded } = props;
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("Auto-detect");
  const [context, setContext] = useState("");
  const [result, setResult] = useState<CodeReviewResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [elapsedSec, setElapsedSec] = useState(0);
  const [exportBusy, setExportBusy] = useState<null | "json" | "csv" | "pdf">(null);
  const [reportPreparedBy, setReportPreparedBy] = useState("");
  const abortRef = useRef<AbortController | null>(null);

  const downloadJson = useCallback(() => {
    if (!result) return;
    const by = reportPreparedBy.trim();
    const payload = by ? { ...result, reportPreparedBy: by } : result;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "argus-code-review.json";
    a.click();
    URL.revokeObjectURL(a.href);
  }, [result, reportPreparedBy]);

  const downloadCsv = useCallback(() => {
    if (!result) return;
    const by = reportPreparedBy.trim();
    const rows: string[][] = [
      [
        "severity",
        "title",
        "category",
        "line",
        "code_preview",
        "source",
        "vulnerability",
        "impact",
        "recommendation",
        "fix",
        "cwe",
      ],
    ];
    if (by) {
      rows.push([
        csvEscape("report_meta"),
        csvEscape("prepared_by"),
        csvEscape(""),
        csvEscape(""),
        csvEscape(by),
        csvEscape(""),
        csvEscape(""),
        csvEscape(""),
        csvEscape(""),
        csvEscape(""),
        csvEscape(""),
      ]);
    }
    for (const f of result.findings as CodeFinding[]) {
      rows.push([
        csvEscape(f.severity),
        csvEscape(f.title),
        csvEscape(f.category),
        csvEscape(f.line != null ? String(f.line) : ""),
        csvEscape(f.evidence ?? ""),
        csvEscape(f.source ?? ""),
        csvEscape(f.vulnerability ?? ""),
        csvEscape(f.impact ?? ""),
        csvEscape(f.recommendation ?? ""),
        csvEscape(f.fix ?? ""),
        csvEscape(f.cwe ?? ""),
      ]);
    }
    const csv = rows.map((r) => r.join(",")).join("\r\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "argus-code-review.csv";
    a.click();
    URL.revokeObjectURL(a.href);
  }, [result, reportPreparedBy]);

  const downloadPdf = useCallback(async () => {
    if (!result) return;
    setExportBusy("pdf");
    try {
      const by = reportPreparedBy.trim();
      const res = await fetch("/api/code-review/pdf", {
        method: "POST",
        headers: jsonHeadersWithArgus(),
        body: JSON.stringify({
          result,
          ...(by ? { reportPreparedBy: by } : {}),
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(typeof err.error === "string" ? err.error : "PDF export failed");
      }
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "argus-code-review.pdf";
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      setError(e instanceof Error ? e.message : "PDF export failed");
    } finally {
      setExportBusy(null);
    }
  }, [result, reportPreparedBy]);

  useEffect(() => {
    if (!loading) {
      setElapsedSec(0);
      return;
    }
    const t0 = Date.now();
    const id = window.setInterval(() => {
      setElapsedSec(Math.floor((Date.now() - t0) / 1000));
    }, 400);
    return () => clearInterval(id);
  }, [loading]);

  const handleCancel = () => {
    abortRef.current?.abort();
  };

  const downloadSemgrepStub = useCallback(() => {
    if (!result) return;
    const yaml = buildSemgrepStubYaml(result);
    const blob = new Blob([yaml], { type: "text/yaml;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "argus-semgrep-stub.yaml";
    a.click();
    URL.revokeObjectURL(a.href);
  }, [result]);

  const handleReview = async () => {
    if (!code.trim()) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    setLoading(true);
    setError("");
    setResult(null);

    const clientMaxMs = 95_000;
    const clientTimer = window.setTimeout(() => ac.abort(), clientMaxMs);

    try {
      const res = await fetch("/api/code-review", {
        method: "POST",
        headers: jsonHeadersWithArgus(),
        body: JSON.stringify({
          code,
          language: language === "Auto-detect" ? null : language,
          context,
        }),
        signal: ac.signal,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(typeof data.error === "string" ? data.error : "Review failed");
      setResult(data as CodeReviewResult);
    } catch (e: unknown) {
      if (e instanceof Error && e.name === "AbortError") {
        setError("Review canceled or client timed out (90s). If the server was slow, try again - static analysis usually returns within seconds.");
      } else {
        setError(e instanceof Error ? e.message : "Review failed");
      }
    } finally {
      window.clearTimeout(clientTimer);
      if (abortRef.current === ac) abortRef.current = null;
      setLoading(false);
    }
  };

  const sevIcon = (severity: string) => {
    switch (severity) {
      case "critical": case "high": return <XCircle className="w-4 h-4 text-danger shrink-0" />;
      case "medium": return <AlertTriangle className="w-4 h-4 text-warning shrink-0" />;
      case "low": return <Info className="w-4 h-4 text-info shrink-0" />;
      default: return <Info className="w-4 h-4 text-text-dim shrink-0" />;
    }
  };

  const riskColor = (risk: string) => {
    switch (risk) {
      case "critical": return "text-red-400 bg-red-400/10";
      case "high": return "text-orange-400 bg-orange-400/10";
      case "medium": return "text-yellow-400 bg-yellow-400/10";
      case "low": return "text-blue-400 bg-blue-400/10";
      default: return "text-green-400 bg-green-400/10";
    }
  };

  return (
    <div className={embedded ? "w-full" : "max-w-5xl mx-auto px-4 py-8"}>
      <div className="bg-surface border border-border rounded-xl overflow-hidden">
        <div className="p-4 border-b border-border flex items-start gap-3">
          <Code2 className="w-5 h-5 text-accent shrink-0 mt-0.5" />
          <div>
            <h3 className="font-semibold text-white">Code security review</h3>
            <p className="text-[11px] text-text-dim mt-1 leading-relaxed">
              Regex/heuristic SAST always runs; optional Semgrep merges when the server sets{" "}
              <span className="font-mono text-text-muted">ARGUS_ENABLE_SEMGREP=1</span> and installs{" "}
              <a href="https://semgrep.dev" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                Semgrep
              </a>{" "}
              (open source). For confirmation beyond this UI, also run{" "}
              <a href="https://github.com/github/codeql-cli-binaries" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                CodeQL
              </a>{" "}
              or{" "}
              <a href="https://owasp.org/www-project-code-review-guide/" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                OWASP Code Review
              </a>
              .
            </p>
          </div>
        </div>

        <div className="p-4 space-y-4">
          <div className="flex flex-wrap gap-3">
            <div className="relative">
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="appearance-none bg-bg border border-border rounded-lg px-3 py-2 pr-8 text-sm text-white focus:outline-none focus:border-accent"
              >
                {LANGUAGES.map((l) => <option key={l} value={l}>{l}</option>)}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-text-dim pointer-events-none" />
            </div>
            <input
              type="text"
              value={context}
              onChange={(e) => setContext(e.target.value)}
              placeholder="Context: e.g., authentication endpoint, payment handler..."
              className="flex-1 min-w-[200px] bg-bg border border-border rounded-lg px-3 py-2 text-sm text-white placeholder:text-text-dim focus:outline-none focus:border-accent"
            />
          </div>

          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste your code here for security analysis..."
            rows={14}
            className="w-full bg-bg border border-border rounded-lg p-4 font-mono text-sm text-text resize-y focus:outline-none focus:border-accent leading-relaxed"
            spellCheck={false}
          />

          <div className="flex items-center justify-between flex-wrap gap-3">
            <span className="text-xs text-text-dim">
              {code.length > 0 ? `${code.split("\n").length} lines · ${code.length} chars` : "No code entered"}
            </span>
            <div className="flex items-center gap-2">
              {loading ? (
                <button
                  type="button"
                  onClick={handleCancel}
                  className="flex items-center gap-2 px-4 py-2.5 border border-border text-text-muted hover:text-white text-sm font-semibold rounded-lg transition-colors"
                >
                  <Square className="w-3.5 h-3.5 fill-current" />
                  Cancel
                </button>
              ) : null}
              <button
                onClick={handleReview}
                disabled={loading || !code.trim()}
                className="flex items-center gap-2 px-6 py-2.5 bg-accent hover:bg-accent-hover text-white font-semibold text-sm rounded-lg disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Analyzing…
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    Run Security Review
                  </>
                )}
              </button>
            </div>
          </div>

          {loading && (
            <div className="space-y-2 rounded-lg border border-border/80 bg-surface-2/40 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-text-dim">
                <span>
                  Elapsed: <span className="text-white font-mono font-semibold">{elapsedSec}s</span>
                  {elapsedSec < TYPICAL_AI_CAP_SECONDS ? (
                    <span className="text-text-dim">
                      {" "}
                      · ~{Math.max(0, TYPICAL_AI_CAP_SECONDS - elapsedSec)}s typical max for AI on server
                    </span>
                  ) : (
                    <span className="text-warning"> · AI may have timed out; finishing request…</span>
                  )}
                </span>
              </div>
              <div className="h-2 w-full rounded-full bg-border overflow-hidden">
                <div
                  className="h-full rounded-full scan-progress-bar transition-[width] duration-500 ease-out"
                  style={{
                    width: `${Math.min(97, 5 + (elapsedSec / TYPICAL_AI_CAP_SECONDS) * 85)}%`,
                  }}
                />
              </div>
              <p className="text-[10px] text-text-dim leading-relaxed">
                Static (SAST) rules run on the server first; if <span className="text-text-muted">GEMINI_API_KEY</span> is set, an AI pass runs too (capped at ~{TYPICAL_AI_CAP_SECONDS}s). The bar is a time estimate, not exact model progress.
              </p>
            </div>
          )}

          {error && (
            <div className="p-3 bg-danger/10 border border-danger/20 rounded-lg text-danger text-sm flex items-center gap-2">
              <XCircle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}
        </div>

        {result && (
          <div className="border-t border-border">
            {result.providerNote && (
              <div className="p-3 mx-4 mt-4 rounded-lg border border-info/40 bg-info/10 text-info text-xs leading-relaxed">
                {result.providerNote}
              </div>
            )}
            <div className="p-4 bg-bg/30 flex flex-wrap items-center gap-5">
              <div className="flex items-center gap-4 min-w-0">
                <SecurityScoreRing score={result.score} />
                <div className="flex items-center gap-2 min-w-0">
                  <Shield className="w-5 h-5 text-accent shrink-0" />
                  <div>
                    <p className="text-sm font-semibold text-white">Security score</p>
                    <p className="text-xs text-text-dim mt-0.5">
                      Ring shows relative posture; details are in findings below.
                    </p>
                  </div>
                </div>
              </div>
              <span className={`text-xs font-semibold px-2.5 py-1 rounded-lg uppercase ${riskColor(result.overallRisk)}`}>
                {result.overallRisk} Risk
              </span>
              <span className="text-xs text-text-dim">
                {result.findings.length} findings
                {typeof result.staticFindingsCount === "number" || typeof result.aiFindingsCount === "number" ? (
                  <span className="text-text-dim ml-1">
                    (
                    {typeof result.staticFindingsCount === "number" ? `${result.staticFindingsCount} static` : ""}
                    {typeof result.staticFindingsCount === "number" && typeof result.aiFindingsCount === "number"
                      ? " · "
                      : ""}
                    {typeof result.aiFindingsCount === "number" ? `${result.aiFindingsCount} AI` : ""})
                  </span>
                ) : null}
              </span>
              {result.reviewSource === "sast" && (
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-info/15 text-info border border-info/30">
                  Static only
                </span>
              )}
              {result.reviewSource === "sast+gemini" && (
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-success/15 text-success border border-success/25">
                  Static + AI
                </span>
              )}
              {(result.reviewSource === "gemini" || result.reviewSource === "heuristic") && (
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-warning/15 text-warning border border-warning/30">
                  {result.reviewSource === "heuristic" ? "Pattern scan" : "AI only"}
                </span>
              )}
            </div>

            <div className="mx-4 mb-4 rounded-xl border border-accent/30 bg-accent/5 p-4 sm:p-5 space-y-3">
              <div>
                <h3 className="text-sm font-semibold text-white">Export report</h3>
                <p className="text-[11px] text-text-dim mt-0.5">
                  Download JSON (full payload), CSV (findings table), or PDF (formatted report).
                </p>
              </div>
              <div className="space-y-1.5">
                <label htmlFor="code-review-prepared-by" className="text-[11px] text-text-dim block">
                  Your name on the report <span className="text-text-muted">(optional)</span>
                </label>
                <input
                  id="code-review-prepared-by"
                  type="text"
                  maxLength={120}
                  value={reportPreparedBy}
                  onChange={(e) => setReportPreparedBy(e.target.value)}
                  placeholder="Shown on PDF / CSV / JSON when set"
                  className="w-full max-w-md rounded-lg border border-border bg-bg px-3 py-2 text-sm text-white placeholder:text-text-dim focus:outline-none focus:ring-2 focus:ring-accent/40"
                />
              </div>
              <div className="flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center gap-2 sm:gap-3">
                <button
                  type="button"
                  onClick={downloadJson}
                  className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded-lg transition-colors"
                >
                  <FileJson className="w-4 h-4" />
                  Download JSON
                </button>
                <button
                  type="button"
                  onClick={downloadCsv}
                  className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded-lg transition-colors"
                >
                  <FileText className="w-4 h-4" />
                  Download CSV
                </button>
                <button
                  type="button"
                  onClick={() => void downloadPdf()}
                  disabled={exportBusy === "pdf"}
                  className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-accent hover:bg-accent-hover disabled:opacity-60 disabled:pointer-events-none text-white text-sm font-semibold rounded-lg transition-colors"
                >
                  {exportBusy === "pdf" ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <FileDown className="w-4 h-4" />
                  )}
                  {exportBusy === "pdf" ? "Building PDF…" : "Download PDF"}
                </button>
                <button
                  type="button"
                  onClick={downloadSemgrepStub}
                  className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-surface-2 hover:bg-border border border-border text-white text-sm font-semibold rounded-lg transition-colors"
                >
                  <Braces className="w-4 h-4" />
                  Semgrep stub (YAML)
                </button>
              </div>
              <p className="text-[10px] text-text-dim">
                The YAML lists one placeholder rule per finding for you to map into real Semgrep patterns or CodeQL queries.
              </p>
            </div>

            <div className="p-4 border-t border-border">
              <p className="text-sm text-text-muted">{result.summary}</p>
            </div>

            {result.findings.length > 0 && (
              <div className="divide-y divide-border">
                {result.findings.map((f, i) => {
                  const cf = f as CodeFinding;
                  const vuln = cf.vulnerability ?? `${cf.title} - ${cf.description}`;
                  const impact = cf.impact ?? "";
                  const rec = cf.recommendation ?? cf.fix ?? "";
                  return (
                    <div key={i} className="p-4 hover:bg-bg/20 transition-colors">
                      <div className="flex items-start gap-3">
                        {sevIcon(cf.severity)}
                        <div className="flex-1 min-w-0 space-y-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-medium text-white">{cf.title}</span>
                            <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded uppercase ${riskColor(cf.severity)}`}>
                              {cf.severity}
                            </span>
                            {cf.cwe && (
                              <a href={`https://cwe.mitre.org/data/definitions/${cf.cwe.replace("CWE-", "")}.html`}
                                target="_blank" rel="noopener noreferrer"
                                className="text-[10px] font-mono text-accent hover:underline">{cf.cwe}</a>
                            )}
                            <span className="text-[10px] text-text-dim bg-bg px-1.5 py-0.5 rounded">{cf.category}</span>
                            {cf.source === "sast" && (
                              <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-info/20 text-info border border-info/30">
                                SAST
                              </span>
                            )}
                            {cf.source === "semgrep" && (
                              <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/35">
                                Semgrep
                              </span>
                            )}
                            {cf.source === "ai" && (
                              <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-accent/20 text-accent border border-accent/30">
                                AI
                              </span>
                            )}
                            {cf.line != null && (
                              <span className="text-[10px] text-text-dim font-mono">Line {cf.line}</span>
                            )}
                          </div>
                          {cf.evidence ? (
                            <p className="text-[11px] font-mono text-accent/90 bg-bg/80 border border-border/60 rounded-md px-2 py-1.5">
                              <span className="text-[9px] uppercase tracking-wider text-text-dim font-sans">
                                At line{" "}
                              </span>
                              {cf.evidence}
                            </p>
                          ) : null}
                          <div className="h-1.5 rounded-full bg-border overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all ${severityBarClass(cf.severity)}`}
                              style={{ width: `${severityBarWidth(cf.severity)}%` }}
                              title="Relative severity indicator (not exact CVSS)"
                            />
                          </div>
                          <div className="rounded-lg border border-border/80 bg-surface-2/30 p-3 space-y-2.5">
                            <div>
                              <p className="text-[10px] uppercase tracking-wider text-accent font-bold">Vulnerability</p>
                              <p className="text-sm text-text-muted leading-relaxed mt-0.5">{vuln}</p>
                            </div>
                            <div>
                              <p className="text-[10px] uppercase tracking-wider text-warning font-bold">Impact</p>
                              <p className="text-sm text-text-muted leading-relaxed mt-0.5">{impact}</p>
                            </div>
                            <div>
                              <p className="text-[10px] uppercase tracking-wider text-success font-bold">Recommendation</p>
                              <p className="text-sm text-text leading-relaxed mt-0.5">{rec}</p>
                            </div>
                            {cf.fix && cf.fix !== rec ? (
                              <div className="pt-1 border-t border-border/60">
                                <p className="text-[10px] uppercase tracking-wider text-text-dim font-bold">Technical hint</p>
                                <p className="text-sm font-mono text-accent mt-0.5 break-all">{cf.fix}</p>
                              </div>
                            ) : null}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {result.recommendations.length > 0 && (
              <div className="p-4 border-t border-border">
                <h4 className="text-xs text-text-dim uppercase tracking-wider mb-2">Recommendations</h4>
                <ul className="space-y-1.5">
                  {result.recommendations.map((r, i) => (
                    <li key={i} className="text-sm text-text-muted flex items-start gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-success mt-0.5 shrink-0" />
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
