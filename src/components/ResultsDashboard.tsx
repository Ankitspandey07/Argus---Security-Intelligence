"use client";
import { useState, useMemo, useCallback } from "react";
import {
  Shield, Lock, Globe, Network, Radio, Cpu, Brain, FileText,
  ChevronDown, ChevronRight, CheckCircle2, XCircle, AlertTriangle,
  ExternalLink, Clock, Server, Cookie,
  FileSearch, Bug, Anchor, Timer, Loader2, Package, ArrowUpRight, Search,
  Mail, ScrollText, BookOpen,
} from "lucide-react";
import ReportExporter from "@/components/ReportExporter";
import type {
  ScanResult, SSLResult, PortScanResult, AIReport,
} from "@/lib/types";
import { gradeColor } from "@/lib/utils";
import { buildLibraryInventory } from "@/lib/library-inventory";
import { evaluateContentSecurityPolicy } from "@/lib/csp-evaluate";
import { jsonHeadersWithArgus } from "@/lib/argus-client-headers";
import type { MailAuthResult, SiteMetaResult, FetchedMeta } from "@/lib/mail-site-types";

function hrefFromFindingSource(raw: string, scanUrl: string): string | null {
  const m = raw.match(/https?:\/\/[^\s)>\]'"]+/i);
  if (m) return m[0];
  try {
    const base = new URL(scanUrl.startsWith("http") ? scanUrl : `https://${scanUrl}`);
    const first = raw.trim().split(/\s+/)[0] || "";
    if (first.startsWith("//")) return `https:${first}`;
    if (first.startsWith("/")) return `${base.origin}${first}`;
    if (first.includes(".") && !first.includes(" ") && !/inline/i.test(raw)) {
      return new URL(`https://${first.replace(/^\/+/, "")}`).href;
    }
  } catch {
    return null;
  }
  return null;
}

interface AllResults {
  scan?: ScanResult;
  ssl?: SSLResult;
  subdomains?: { domain: string; count: number; subdomains: { subdomain: string; source: string }[] };
  ports?: PortScanResult & {
    cves?: string[];
    tags?: string[];
    highRiskOpenPorts?: { port: number; service: string; exposureRisk?: string; exposureReason?: string }[];
    highRiskOpenPortsCount?: number;
  };
  sourceAudit?: Record<string, unknown>;
  virustotal?: Record<string, unknown>;
  takeover?: Record<string, unknown>;
  wpCron?: Record<string, unknown>;
  googleDork?: Record<string, unknown>;
  ai?: AIReport;
  mailAuth?: MailAuthResult;
  siteMeta?: SiteMetaResult;
}

function isFetchedMeta(x: FetchedMeta | { skipped: true; reason: string }): x is FetchedMeta {
  return !("skipped" in x && x.skipped);
}

function StatusBadge({ status }: { status: "pass" | "fail" | "warn" }) {
  if (status === "pass") return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-success/10 text-success"><CheckCircle2 className="w-3 h-3" />Pass</span>;
  if (status === "fail") return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-danger/10 text-danger"><XCircle className="w-3 h-3" />Fail</span>;
  return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-warning/10 text-warning"><AlertTriangle className="w-3 h-3" />Warn</span>;
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-blue-500", info: "bg-gray-500",
  };
  return <span className={`w-2 h-2 rounded-full shrink-0 ${colors[severity] || colors.info}`} />;
}

function Panel({ title, icon: Icon, children, defaultOpen = true, count }: {
  title: string; icon: React.ElementType; children: React.ReactNode; defaultOpen?: boolean; count?: number;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-surface border border-border rounded-xl overflow-hidden animate-fade-up">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-3 p-4 hover:bg-surface-2/50 transition-colors text-left">
        <Icon className="w-5 h-5 text-accent shrink-0" />
        <span className="font-semibold text-white text-sm flex-1">{title}</span>
        {count !== undefined && <span className="text-xs font-mono text-text-dim bg-bg px-2 py-0.5 rounded">{count}</span>}
        {open ? <ChevronDown className="w-4 h-4 text-text-dim" /> : <ChevronRight className="w-4 h-4 text-text-dim" />}
      </button>
      {open && <div className="border-t border-border">{children}</div>}
    </div>
  );
}

function SecurityScore({ score, grade }: { score: number; grade: string }) {
  const color = gradeColor(grade);
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="bg-surface border border-border rounded-xl p-6 animate-fade-up">
      <div className="flex flex-col sm:flex-row items-center gap-6">
        <div className="relative w-32 h-32 shrink-0">
          <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="54" fill="none" stroke="currentColor" strokeWidth="8" className="text-border" />
            <circle cx="60" cy="60" r="54" fill="none" stroke={color} strokeWidth="8"
              strokeDasharray={circumference} strokeDashoffset={offset}
              strokeLinecap="round" className="transition-all duration-1000" />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-bold" style={{ color }}>{grade}</span>
            <span className="text-xs text-text-dim font-mono">{score}/100</span>
          </div>
        </div>
        <div className="flex-1 text-center sm:text-left">
          <h3 className="text-xl font-bold text-white mb-1">Security Score</h3>
          <p className="text-sm text-text-muted mb-3">
            {score >= 80 ? "Strong security posture with minor improvements possible." :
             score >= 60 ? "Moderate security. Several headers and configurations need attention." :
             score >= 40 ? "Weak security posture. Multiple critical issues found." :
             "Critical security issues. Immediate action required."}
          </p>
        </div>
      </div>
    </div>
  );
}

function TargetInfo({ scan }: { scan: ScanResult }) {
  return (
    <div className="bg-surface border border-border rounded-xl p-4 animate-fade-up">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div>
          <div className="text-xs text-text-dim mb-1">Target</div>
          <div className="text-sm font-mono text-white truncate">{scan.target.hostname}</div>
        </div>
        <div>
          <div className="text-xs text-text-dim mb-1">IP Address</div>
          <div className="text-sm font-mono text-white">{scan.target.ip || "N/A"}</div>
        </div>
        <div>
          <div className="text-xs text-text-dim mb-1 flex items-center gap-1"><Clock className="w-3 h-3" />Response</div>
          <div className="text-sm font-mono text-white">{scan.responseTime}ms</div>
        </div>
        <div>
          <div className="text-xs text-text-dim mb-1 flex items-center gap-1"><Server className="w-3 h-3" />Status</div>
          <div className="text-sm font-mono text-white">{scan.statusCode}</div>
        </div>
      </div>
    </div>
  );
}

export default function ResultsDashboard({
  results,
  onResultsPatch,
}: {
  results: AllResults;
  onResultsPatch?: (patch: Partial<AllResults>) => void;
}) {
  const { scan, ssl, subdomains, ports, ai, sourceAudit, virustotal, takeover, wpCron, googleDork, mailAuth, siteMeta } = results;
  if (!scan) return null;

  const [takeoverExtendLoading, setTakeoverExtendLoading] = useState(false);
  const [vtShowRaw, setVtShowRaw] = useState(false);

  const libraryInventory = useMemo(() => {
    if (!sourceAudit || typeof sourceAudit !== "object" || "error" in sourceAudit) return null;
    const sa = sourceAudit as Record<string, unknown>;
    return buildLibraryInventory({
      scan,
      scriptUrls: Array.isArray(sa.scriptUrls) ? (sa.scriptUrls as string[]) : undefined,
      detectedJsLibraries: Array.isArray(sa.detectedJsLibraries)
        ? (sa.detectedJsLibraries as { library: string; version: string; url: string; evidence: string }[])
        : undefined,
      libraryRisks: Array.isArray(sa.libraryRisks)
        ? (sa.libraryRisks as { library: string; version: string | null; severity: string; note: string; url: string }[])
        : undefined,
      retireMatches: Array.isArray(sa.retireMatches)
        ? (sa.retireMatches as { library: string; version: string; scriptUrl: string; summary: string; cves: string[] }[])
        : undefined,
    });
  }, [scan, sourceAudit]);

  const runExtendedTakeover = useCallback(async () => {
    if (!onResultsPatch || !subdomains?.subdomains?.length) return;
    setTakeoverExtendLoading(true);
    try {
      const hosts = [
        scan.target.hostname,
        ...subdomains.subdomains.map((s) => s.subdomain),
      ];
      const res = await fetch("/api/takeover-scan", {
        method: "POST",
        headers: jsonHeadersWithArgus(),
        body: JSON.stringify({ hosts, maxHosts: 150 }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      onResultsPatch({ takeover: data });
    } catch (e) {
      alert(e instanceof Error ? e.message : "Extended takeover scan failed");
    } finally {
      setTakeoverExtendLoading(false);
    }
  }, [onResultsPatch, scan.target.hostname, subdomains]);

  const passCount = scan.headers.filter(h => h.status === "pass").length;
  const failCount = scan.headers.filter(h => h.status === "fail").length;
  const warnCount = scan.headers.filter(h => h.status === "warn").length;

  const corsHeader = scan.headers.find((h) => /access-control-allow-origin/i.test(h.name));

  const cspHeaderRow = scan.headers.find((h) => h.name === "Content-Security-Policy");
  const cspRaw =
    cspHeaderRow && cspHeaderRow.value !== "Missing" && cspHeaderRow.value.trim()
      ? cspHeaderRow.value
      : null;
  const cspEval = useMemo(() => evaluateContentSecurityPolicy(cspRaw), [cspRaw]);

  const takeoverHosts = Array.isArray(takeover?.hostsScanned) ? (takeover!.hostsScanned as string[]).length : 0;
  const isQuickTakeoverOnly = takeoverHosts > 0 && takeoverHosts <= 2 && (subdomains?.count ?? 0) > 0;

  const vtExportPayload = useMemo(() => {
    if (!virustotal || typeof virustotal !== "object") return null;
    if ("skipped" in virustotal && virustotal.skipped) return null;
    if ("error" in virustotal && virustotal.error) return null;
    const v = virustotal as Record<string, unknown>;
    if (v.vtFullExport && typeof v.vtFullExport === "object") return v.vtFullExport as Record<string, unknown>;
    return {
      _meta: {
        partial: true,
        note: "Re-run scan to pull full vtFullExport from API (this payload is merged from summary fields).",
        domain: v.domain,
      },
      categories: v.categories,
      detected_urls: v.detectedUrls,
      detected_communicating_samples: v.detectedCommunicatingSamples,
      detected_downloaded_samples: v.detectedDownloadedSamples,
      whois: v.whois,
      subdomains: v.subdomains,
      resolutions: v.resolutions,
      undetected_urls: v.undetectedUrls,
      pcaps: v.pcaps,
    };
  }, [virustotal]);

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 space-y-4">
      <SecurityScore score={scan.score} grade={scan.grade} />
      <TargetInfo scan={scan} />

      <div className="rounded-xl border border-border bg-surface/60 px-4 py-3 text-[11px] text-text-muted space-y-2 animate-fade-up">
        <div className="font-semibold text-white text-xs flex items-center gap-2">
          <Globe className="w-4 h-4 text-accent" />
          CORS (from main page response)
        </div>
        {corsHeader ? (
          <p>
            <span className="font-mono text-text-dim">{corsHeader.name}</span>:{" "}
            <span className="font-mono text-white break-all">{corsHeader.value}</span>
            {/\*/.test(corsHeader.value) ? (
              <span className="block mt-1 text-warning">Wildcard origins can be risky when cookies or credentials are involved — verify with OWASP CORS guidance.</span>
            ) : null}
          </p>
        ) : (
          <p className="text-text-dim">No Access-Control-Allow-Origin on the scanned response (typical for same-origin HTML).</p>
        )}
      </div>

      <ReportExporter results={results} />

      {mailAuth && (
        <Panel title="Mail authentication (DNS)" icon={Mail} defaultOpen={false}>
          <div className="p-4 space-y-3 text-sm text-text-muted">
            <p className="text-[11px] text-text-dim">
              Checked hosts: <span className="font-mono text-white">{mailAuth.checkedHosts.join(", ")}</span>
            </p>
            <div>
              <div className="text-xs font-semibold text-white mb-1">MX</div>
              {mailAuth.mx.length === 0 ? (
                <p className="text-xs">None returned for this hostname.</p>
              ) : (
                <ul className="font-mono text-xs space-y-1">
                  {mailAuth.mx.map((m) => (
                    <li key={m.exchange}>
                      {m.priority} {m.exchange}
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <div className="text-xs font-semibold text-white mb-1">SPF (TXT)</div>
              {mailAuth.spf ? (
                <p className="font-mono text-xs break-all bg-bg/80 border border-border rounded p-2">{mailAuth.spf.record}</p>
              ) : (
                <p className="text-xs text-warning">No v=spf1 TXT found on checked hosts.</p>
              )}
            </div>
            <div>
              <div className="text-xs font-semibold text-white mb-1">DMARC</div>
              {mailAuth.dmarc ? (
                <p className="font-mono text-xs break-all bg-bg/80 border border-border rounded p-2">{mailAuth.dmarc.record}</p>
              ) : (
                <p className="text-xs text-warning">No v=DMARC1 record on _dmarc.* for checked hosts.</p>
              )}
            </div>
            {mailAuth.notes.length > 0 && (
              <ul className="text-xs list-disc pl-4 space-y-1">
                {mailAuth.notes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            )}
          </div>
        </Panel>
      )}

      {siteMeta && (
        <Panel title="robots.txt & security.txt" icon={ScrollText} defaultOpen={false}>
          <div className="p-4 space-y-4 text-sm">
            {(["robots", "securityTxt"] as const).map((key) => {
              const block = siteMeta[key];
              const label = key === "robots" ? "/robots.txt" : "/.well-known/security.txt";
              return (
                <div key={key} className="border border-border rounded-lg p-3 bg-bg/30">
                  <div className="text-xs font-semibold text-white mb-2">{label}</div>
                  {isFetchedMeta(block) ? (
                    <>
                      <p className="text-[11px] text-text-dim mb-1">
                        HTTP {block.status} ·{" "}
                        <a href={block.finalUrl} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline font-mono break-all">
                          {block.finalUrl}
                        </a>
                      </p>
                      {block.accessControlAllowOrigin ? (
                        <p className="text-[10px] text-text-dim mb-2">
                          Access-Control-Allow-Origin:{" "}
                          <span className="font-mono text-warning">{block.accessControlAllowOrigin}</span>
                        </p>
                      ) : null}
                      <pre className="text-[10px] font-mono text-text-muted whitespace-pre-wrap max-h-40 overflow-y-auto border border-border/60 rounded p-2 bg-bg">
                        {block.excerpt || "(empty body)"}
                      </pre>
                    </>
                  ) : (
                    <p className="text-xs text-text-dim">Skipped: {(block as { reason: string }).reason}</p>
                  )}
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      <div className="rounded-xl border border-border bg-accent/5 px-4 py-3 animate-fade-up">
        <div className="flex items-center gap-2 text-xs font-semibold text-white mb-2">
          <BookOpen className="w-4 h-4 text-accent" />
          Free public references (no account)
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-2 text-[11px]">
          <a href="https://owasp.org/www-project-web-security-testing-guide/" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
            OWASP WSTG
          </a>
          <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
            MDN — CORS
          </a>
          <a href="https://www.rfc-editor.org/rfc/rfc9116" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
            RFC 9116 (security.txt)
          </a>
          <a href="https://semgrep.dev" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
            Semgrep (open source)
          </a>
        </div>
      </div>

      {sourceAudit && typeof sourceAudit === "object" && !("error" in sourceAudit) && (
        <Panel
          title="Source leak scan (HTML + JS)"
          icon={FileSearch}
          count={Array.isArray(sourceAudit.secretFindings) ? sourceAudit.secretFindings.length : 0}
        >
          <div className="p-4 space-y-4">
            <div className="flex flex-wrap items-center gap-3 text-[11px] text-text-dim rounded-lg border border-border bg-bg/40 px-3 py-2">
              <span>
                Pages: <span className="font-mono text-text-muted">{String(sourceAudit.pagesCrawled ?? "—")}</span>
              </span>
              <span className="text-border">|</span>
              <span>
                Scripts (sample):{" "}
                <span className="font-mono text-text-muted">
                  {Array.isArray(sourceAudit.scriptUrlsSample) ? sourceAudit.scriptUrlsSample.length : 0}
                </span>
              </span>
              <span className="text-border">|</span>
              <span>
                Tracked URLs:{" "}
                <span className="font-mono text-text-muted">
                  {Array.isArray((sourceAudit as { scriptUrls?: unknown[] }).scriptUrls)
                    ? (sourceAudit as { scriptUrls: unknown[] }).scriptUrls.length
                    : 0}
                </span>
              </span>
            </div>
            {typeof sourceAudit.summary === "object" && sourceAudit.summary !== null && (
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                {Object.entries(sourceAudit.summary as Record<string, number>).map(([k, v]) => (
                  <span key={k} className="px-2 py-1 rounded bg-bg border border-border text-text-muted">
                    {k}: <span className="text-white">{v}</span>
                  </span>
                ))}
              </div>
            )}
            <div className="text-[11px] font-semibold text-white uppercase tracking-wider border-b border-border pb-1">
              Sensitive patterns (redacted)
            </div>
            {Array.isArray(sourceAudit.secretFindings) && sourceAudit.secretFindings.length > 0 ? (
              <div className="space-y-2 max-h-72 overflow-y-auto">
                {(sourceAudit.secretFindings as {
                  label: string;
                  severity: string;
                  redacted: string;
                  sourceUrl: string;
                  hint: string;
                  jwtDecoded?: unknown;
                  lineNumber?: number;
                  columnApprox?: number;
                  contextSnippet?: string;
                  locateHint?: string;
                }[]).map((f, i) => {
                  const link = hrefFromFindingSource(f.sourceUrl, scan.target.url);
                  return (
                    <div key={i} className="p-3 rounded-lg bg-bg border border-border text-xs space-y-2">
                      <div className="flex items-start justify-between gap-2 flex-wrap">
                        <div className="flex items-center gap-2 flex-wrap min-w-0">
                          <SeverityDot severity={f.severity} />
                          <span className="font-medium text-white">{f.label}</span>
                          <span className="font-mono text-accent">{f.redacted}</span>
                          {typeof f.lineNumber === "number" ? (
                            <span className="text-[10px] font-mono text-text-dim bg-surface-2 px-1.5 py-0.5 rounded">
                              Line {f.lineNumber}
                              {typeof f.columnApprox === "number" ? ` :${f.columnApprox}` : ""}
                            </span>
                          ) : null}
                        </div>
                        {link ? (
                          <a
                            href={link}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 shrink-0 px-2 py-1 rounded-md bg-accent/15 text-accent text-[10px] font-semibold hover:bg-accent/25 border border-accent/30"
                          >
                            Open source
                            <ArrowUpRight className="w-3 h-3" />
                          </a>
                        ) : (
                          <span className="text-[10px] text-text-dim shrink-0 px-2 py-1 rounded border border-border">
                            Inline / no URL
                          </span>
                        )}
                      </div>
                      <p className="text-text-dim break-all font-mono text-[10px]">{f.sourceUrl}</p>
                      {f.contextSnippet ? (
                        <div className="rounded-md border border-border/80 bg-surface-2/50 px-2 py-1.5">
                          <div className="text-[9px] uppercase tracking-wider text-accent mb-0.5">Where it appears (secret removed)</div>
                          <p className="text-[11px] text-text-muted font-mono leading-relaxed break-all">{f.contextSnippet}</p>
                        </div>
                      ) : null}
                      {f.locateHint ? (
                        <p className="text-[11px] text-text-dim leading-relaxed border-l-2 border-info/40 pl-2">{f.locateHint}</p>
                      ) : null}
                      <p className="text-text-muted">{f.hint}</p>
                      {f.jwtDecoded != null ? (
                        <pre className="text-[10px] font-mono text-warning overflow-x-auto">
                          {JSON.stringify(f.jwtDecoded as object, null, 2)}
                        </pre>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-xs text-success">No high-signal secret patterns matched in crawled content.</p>
            )}
            {typeof (sourceAudit as { awsLeakScan?: unknown }).awsLeakScan === "object" &&
              (sourceAudit as { awsLeakScan: Record<string, unknown> }).awsLeakScan !== null && (
                <div className="rounded-lg border border-warning/30 bg-warning/5 p-3 space-y-3">
                  <div className="text-[11px] font-semibold text-white uppercase tracking-wider flex items-center gap-2">
                    <Server className="w-4 h-4 text-warning shrink-0" />
                    AWS-related leak checks (crawl + host probes)
                  </div>
                  <p className="text-[11px] text-text-dim leading-relaxed">
                    {(sourceAudit as { awsLeakScan: { note?: string } }).awsLeakScan.note}
                  </p>
                  {Array.isArray((sourceAudit as { awsLeakScan: { secretFindings?: unknown[] } }).awsLeakScan.secretFindings) &&
                  ((sourceAudit as { awsLeakScan: { secretFindings: unknown[] } }).awsLeakScan.secretFindings as {
                    label: string;
                    severity: string;
                    redacted: string;
                    sourceUrl: string;
                    hint: string;
                  }[]).length > 0 ? (
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      <div className="text-[10px] uppercase text-text-dim">From crawled HTML/JS (AWS-pattern filter)</div>
                      {(
                        (sourceAudit as { awsLeakScan: { secretFindings: {
                          label: string;
                          severity: string;
                          redacted: string;
                          sourceUrl: string;
                          hint: string;
                        }[] } }).awsLeakScan.secretFindings
                      ).map((f, i) => {
                        const link = hrefFromFindingSource(f.sourceUrl, scan.target.url);
                        return (
                          <div key={`aws-${i}`} className="p-2 rounded bg-bg border border-border text-xs space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <SeverityDot severity={f.severity} />
                              <span className="text-white font-medium">{f.label}</span>
                              <span className="font-mono text-accent">{f.redacted}</span>
                            </div>
                            <p className="text-[10px] font-mono text-text-dim break-all">{f.sourceUrl}</p>
                            {link ? (
                              <a
                                href={link}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-[10px] text-accent hover:underline"
                              >
                                Open source <ArrowUpRight className="w-3 h-3" />
                              </a>
                            ) : null}
                            <p className="text-text-dim text-[11px]">{f.hint}</p>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="text-xs text-success">No AWS-specific pattern filter matched in crawled content.</p>
                  )}
                  {Array.isArray((sourceAudit as { awsLeakScan: { probes?: unknown[] } }).awsLeakScan.probes) ? (
                    <div className="space-y-2">
                      <div className="text-[10px] uppercase text-text-dim">HTTP probes on your host (config-style paths)</div>
                      <div className="max-h-56 overflow-y-auto space-y-1.5">
                        {(
                          (sourceAudit as { awsLeakScan: { probes: { path: string; url: string; status: number; signal: string; detail: string }[] } })
                            .awsLeakScan.probes
                        ).map((p, i) => (
                          <div
                            key={i}
                            className={`p-2 rounded border text-[11px] ${
                              p.signal === "aws_signal" ? "border-danger/40 bg-danger/5" : "border-border bg-bg/50"
                            }`}
                          >
                            <div className="flex flex-wrap items-center gap-2 font-mono text-text-muted">
                              <span className="text-white">{p.path}</span>
                              <span>HTTP {p.status}</span>
                              {p.signal === "aws_signal" ? (
                                <span className="text-danger font-semibold">Possible AWS material</span>
                              ) : (
                                <span className="text-text-dim">—</span>
                              )}
                            </div>
                            <p className="text-text-dim mt-1 leading-relaxed">{p.detail}</p>
                            {p.signal === "aws_signal" ? (
                              <a
                                href={p.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-[10px] text-accent mt-1 hover:underline"
                              >
                                Open URL <ArrowUpRight className="w-3 h-3" />
                              </a>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              )}
            <div className="text-[11px] font-semibold text-white uppercase tracking-wider border-b border-border pb-1 pt-2">
              Libraries, script URLs &amp; CVE matches
            </div>
            {Array.isArray(sourceAudit.libraryRisks) && (sourceAudit.libraryRisks as unknown[]).length > 0 && (
              <div>
                <div className="text-xs text-text-dim uppercase tracking-wider mb-2">Heuristic warnings (old versions from URL paths)</div>
                <div className="space-y-2">
                  {(sourceAudit.libraryRisks as { library: string; version: string | null; severity: string; note: string; url: string }[]).map((r, i) => (
                    <div key={i} className="p-2 rounded bg-warning/5 border border-warning/20 text-xs">
                      <span className="text-warning font-medium">{r.library}</span>
                      {r.version && <span className="text-text-dim ml-2 font-mono">v{r.version}</span>}
                      <p className="text-text-muted mt-1">{r.note}</p>
                      <p className="text-[10px] font-mono text-text-dim break-all mt-1">{r.url}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div className="rounded-lg border border-border bg-bg/40 p-3 space-y-2">
              <div className="text-xs text-text-dim uppercase tracking-wider">Known vulnerable JS (Retire-style DB)</div>
              {Array.isArray(sourceAudit.retireMatches) && (sourceAudit.retireMatches as unknown[]).length > 0 ? (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {(sourceAudit.retireMatches as {
                    library: string;
                    version: string;
                    cves: string[];
                    summary: string;
                    scriptUrl: string;
                    references?: string[];
                    detectionSource?: string;
                  }[]).map((r, i) => (
                    <div key={i} className="p-3 rounded-lg bg-danger/5 border border-danger/20 text-xs">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-semibold text-white">{r.library}</span>
                        <span className="font-mono text-accent">v{r.version}</span>
                        {r.detectionSource === "content" ? (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-warning/15 text-warning">from JS content</span>
                        ) : r.detectionSource === "url" ? (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-bg border border-border text-text-dim">from URL</span>
                        ) : null}
                        {(r.cves || []).map((c) => (
                          <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer" className="text-[10px] font-mono text-danger hover:underline">{c}</a>
                        ))}
                      </div>
                      <p className="text-text-muted mt-1">{r.summary}</p>
                      <p className="text-[10px] font-mono text-text-dim break-all mt-1">{r.scriptUrl}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-success">
                  No known vulnerable library versions matched in the Retire.js database for crawled script URLs and fetched JS bodies.
                </p>
              )}
            </div>

            {libraryInventory && libraryInventory.items.length > 0 && (
              <div className="rounded-lg border border-info/30 bg-info/5 p-3 space-y-3">
                <div className="flex items-center gap-2 text-xs text-text-dim uppercase tracking-wider">
                  <Package className="w-4 h-4 text-info shrink-0" />
                  All libraries &amp; frameworks detected
                </div>
                <div className="flex flex-wrap gap-2 text-xs font-mono">
                  <span className="px-2 py-1 rounded bg-success/15 text-success border border-success/25">
                    {libraryInventory.passed} passed
                  </span>
                  <span className="px-2 py-1 rounded bg-danger/15 text-danger border border-danger/25">
                    {libraryInventory.failed} failed
                  </span>
                  <span className="px-2 py-1 rounded bg-warning/15 text-warning border border-warning/25">
                    {libraryInventory.warned} warnings
                  </span>
                  <span className="text-[10px] text-text-dim self-center">{libraryInventory.explanation}</span>
                </div>
                <div className="max-h-56 overflow-y-auto space-y-1.5">
                  {libraryInventory.items.map((it) => (
                    <div
                      key={it.id}
                      className={`text-[11px] px-2 py-2 rounded-lg border ${
                        it.status === "fail"
                          ? "border-danger/40 bg-danger/5"
                          : it.status === "warn"
                            ? "border-warning/40 bg-warning/5"
                            : "border-border bg-bg/50"
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-white">{it.name}</span>
                        {it.version ? (
                          <span className="font-mono text-accent text-[10px]">v{it.version}</span>
                        ) : null}
                        <span
                          className={`text-[10px] font-semibold uppercase ${
                            it.status === "fail"
                              ? "text-danger"
                              : it.status === "warn"
                                ? "text-warning"
                                : "text-success"
                          }`}
                        >
                          {it.status}
                        </span>
                        <span className="text-[10px] text-text-dim">({it.source})</span>
                      </div>
                      <p className="text-text-dim mt-1 leading-relaxed">{it.detail}</p>
                      {it.referenceUrl ? (
                        <p className="text-[10px] font-mono text-text-dim break-all mt-1">{it.referenceUrl}</p>
                      ) : null}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Panel>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Security Headers */}
        <Panel title="Security Headers" icon={Shield} count={scan.headers.length} defaultOpen>
          <div className="divide-y divide-border">
            {scan.headers.map((h) => (
              <div key={h.name} className="p-4 hover:bg-bg/30 transition-colors">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityDot severity={h.severity} />
                  <span className="text-sm font-medium text-white flex-1">{h.name}</span>
                  <StatusBadge status={h.status} />
                </div>
                <p className="text-xs text-text-muted mt-1 ml-4">{h.description}</p>
                {h.status !== "pass" && (
                  <p className="text-xs text-accent mt-1 ml-4">{h.remediation}</p>
                )}
                <div className="mt-1 ml-4">
                  <span className="text-[11px] font-mono text-text-dim bg-bg px-1.5 py-0.5 rounded">
                    {h.value.substring(0, 80)}{h.value.length > 80 ? "..." : ""}
                  </span>
                </div>
              </div>
            ))}
          </div>
          <div className="p-4 border-t border-border space-y-3">
            <div className="text-[11px] font-semibold text-white uppercase tracking-wider">CSP evaluation</div>
            <div
              className={`rounded-lg border p-3 ${
                cspEval.issues.some((i) => i.severity === "critical" || i.severity === "high")
                  ? "border-warning/40 bg-warning/5"
                  : "border-success/30 bg-success/5"
              }`}
            >
              <div className="flex flex-wrap items-center gap-2 mb-2">
                <span className="text-sm font-mono text-accent">Score {cspEval.score}/100</span>
                <span className="text-xs text-text-muted">{cspEval.summary}</span>
              </div>
              {cspEval.issues.length > 0 ? (
                <ul className="space-y-2 text-xs">
                  {cspEval.issues.map((issue) => (
                    <li
                      key={issue.id}
                      className={`rounded-md border px-2 py-1.5 ${
                        issue.severity === "critical" || issue.severity === "high"
                          ? "border-danger/40 bg-danger/5 text-text-muted"
                          : "border-border bg-bg/50 text-text-dim"
                      }`}
                    >
                      <span className="font-semibold text-white">{issue.title}</span>
                      <span className="text-[10px] uppercase text-text-dim ml-2">({issue.severity})</span>
                      <p className="text-[11px] mt-0.5 leading-relaxed">{issue.detail}</p>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          </div>
          <div className="p-4 bg-bg/30 flex gap-4 text-xs">
            <span className="text-success">{passCount} passed</span>
            <span className="text-danger">{failCount} failed</span>
            <span className="text-warning">{warnCount} warnings</span>
          </div>
        </Panel>

        {/* SSL/TLS */}
        {ssl && !("error" in ssl) && (
          <Panel title="SSL / TLS Analysis" icon={Lock}>
            <div className="p-4 space-y-4">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-12 h-12 rounded-lg flex items-center justify-center text-xl font-bold"
                  style={{ background: gradeColor(ssl.grade) + "15", color: gradeColor(ssl.grade) }}>
                  {ssl.grade}
                </div>
                <div>
                  <div className="text-sm font-medium text-white">SSL Grade: {ssl.grade}</div>
                  <div className="text-xs text-text-muted">Protocol: {ssl.protocol}</div>
                </div>
              </div>
              {ssl.probeContext?.likelyCorporateTlsInspection && ssl.probeContext.notes.length > 0 ? (
                <div className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-[11px] text-warning leading-relaxed">
                  <span className="font-semibold text-warning">TLS inspection detected: </span>
                  {ssl.probeContext.notes[0]}
                  {ssl.probeContext.notes[1] ? (
                    <span className="block mt-2 text-text-muted">{ssl.probeContext.notes[1]}</span>
                  ) : null}
                </div>
              ) : null}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-bg rounded-lg p-3">
                  <div className="text-[11px] text-text-dim uppercase tracking-wider">Issuer</div>
                  <div className="text-sm font-mono text-white mt-0.5 truncate">{ssl.issuer}</div>
                </div>
                <div className="bg-bg rounded-lg p-3">
                  <div className="text-[11px] text-text-dim uppercase tracking-wider">Expires</div>
                  <div className="text-sm font-mono text-white mt-0.5">
                    {ssl.daysUntilExpiry > 0 ? `${ssl.daysUntilExpiry} days` : "EXPIRED"}
                  </div>
                </div>
                <div className="bg-bg rounded-lg p-3">
                  <div className="text-[11px] text-text-dim uppercase tracking-wider">Key Size</div>
                  <div className="text-sm font-mono text-white mt-0.5">{ssl.keySize || "N/A"} bits</div>
                </div>
                <div className="bg-bg rounded-lg p-3">
                  <div className="text-[11px] text-text-dim uppercase tracking-wider">Algorithm</div>
                  <div className="text-sm font-mono text-white mt-0.5 truncate">{ssl.signatureAlgorithm}</div>
                </div>
              </div>
              <div>
                <div className="text-xs text-text-dim uppercase tracking-wider mb-2">Protocol Support</div>
                <div className="flex flex-wrap gap-2">
                  {ssl.protocols.map(p => (
                    <span key={p.name} className={`text-xs font-mono px-2 py-1 rounded ${
                      p.supported
                        ? (p.name === "TLSv1" || p.name === "TLSv1.1" ? "bg-danger/10 text-danger" : "bg-success/10 text-success")
                        : "bg-bg text-text-dim"
                    }`}>
                      {p.name} {p.supported ? "✓" : "✗"}
                    </span>
                  ))}
                </div>
              </div>
              {ssl.negotiatedCipher?.name ? (
                <div
                  className={`rounded-lg border p-3 ${
                    ssl.cipherStrength === "weak"
                      ? "border-danger/40 bg-danger/10"
                      : ssl.cipherStrength === "acceptable"
                        ? "border-warning/35 bg-warning/5"
                        : "border-success/30 bg-success/5"
                  }`}
                >
                  <div className="text-xs text-text-dim uppercase tracking-wider mb-1">Negotiated cipher (probe)</div>
                  <p className="text-sm font-mono text-white break-all">{ssl.negotiatedCipher.name}</p>
                  <p className="text-[11px] text-text-muted mt-1">
                    {ssl.cipherStrength === "weak"
                      ? "Weak or legacy primitives detected — prioritize TLS 1.3 / ECDHE + AEAD."
                      : ssl.cipherStrength === "acceptable"
                        ? "Acceptable for many sites; consider modern suites if you need stricter baselines."
                        : "No weak patterns flagged on this negotiated suite name."}
                  </p>
                  {ssl.cipherIssues && ssl.cipherIssues.length > 0 ? (
                    <ul className="mt-2 space-y-1 text-[11px] text-text-muted">
                      {ssl.cipherIssues.map((c, i) => (
                        <li key={i}>
                          <span className="text-warning font-medium">{c.title}:</span> {c.description}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>
              ) : null}
              {ssl.vulnerabilities.length > 0 && (
                <div>
                  <div className="text-xs text-text-dim uppercase tracking-wider mb-2">Issues</div>
                  {ssl.vulnerabilities.filter(v => v.vulnerable).map((v, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs text-danger mb-1">
                      <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
                      <span>{v.name}: {v.description}</span>
                    </div>
                  ))}
                </div>
              )}
              {ssl.certChain.length > 0 && (
                <div>
                  <div className="text-xs text-text-dim uppercase tracking-wider mb-2">Certificate Chain</div>
                  {ssl.certChain.map((c, i) => (
                    <div key={i} className="text-xs font-mono text-text-muted ml-[calc(0.75rem*var(--depth))]" style={{ "--depth": i } as React.CSSProperties}>
                      {i > 0 && "└─ "}{c.subject || c.issuer}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Panel>
        )}

        {/* Subdomains */}
        {subdomains && !("error" in subdomains) && (
          <div className="lg:col-span-2">
          <Panel title="Subdomain Discovery" icon={Network} count={subdomains.count}>
            <div className="p-4">
              <p className="text-xs text-text-dim mb-3">
                Found via Certificate Transparency logs and DNS enumeration. For <strong className="text-white">takeover risk</strong>, use the{" "}
                <strong className="text-accent">Subdomain takeover</strong> section directly below.
              </p>
              <div className="max-h-64 overflow-y-auto space-y-1">
                {subdomains.subdomains.slice(0, 100).map((s, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs group hover:bg-bg/30 px-2 py-1 rounded">
                    <Globe className="w-3 h-3 text-text-dim shrink-0" />
                    <span className="font-mono text-text-muted flex-1 truncate">{s.subdomain}</span>
                    <span className="text-[10px] text-text-dim hidden group-hover:inline">{s.source}</span>
                    <a href={`https://${s.subdomain}`} target="_blank" rel="noopener noreferrer"
                      className="opacity-0 group-hover:opacity-100 transition-opacity">
                      <ExternalLink className="w-3 h-3 text-text-dim hover:text-accent" />
                    </a>
                  </div>
                ))}
              </div>
              {subdomains.count > 100 && (
                <p className="text-xs text-text-dim mt-2">Showing 100 of {subdomains.count} subdomains.</p>
              )}
            </div>
          </Panel>
          </div>
        )}

        {takeover && typeof takeover === "object" && !("error" in takeover) && (
          <div className="lg:col-span-2">
            <Panel
              title="Subdomain takeover heuristics"
              icon={Anchor}
              count={typeof takeover.riskyCount === "number" ? takeover.riskyCount : 0}
              defaultOpen
            >
              <div className="p-4 text-xs space-y-3">
                <p className="text-text-dim leading-relaxed">
                  DNS + HTTPS heuristics (CNAME targets, NXDOMAIN, SaaS error pages — Nuclei/subjack-style signals). Apex-only on first scan; extend below when subdomains exist.
                </p>
                {onResultsPatch && subdomains && subdomains.subdomains.length > 0 && (
                  <button
                    type="button"
                    disabled={takeoverExtendLoading}
                    onClick={runExtendedTakeover}
                    className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-50 text-white text-sm font-semibold transition-colors"
                  >
                    {takeoverExtendLoading ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Anchor className="w-4 h-4" />
                    )}
                    {takeoverExtendLoading ? "Scanning all subdomains…" : "Analyze all discovered subdomains for takeover"}
                  </button>
                )}
                <div
                  className={`rounded-lg border p-3 ${
                    (takeover.riskyCount as number) > 0
                      ? "border-danger/50 bg-danger/10"
                      : "border-success/40 bg-success/10"
                  }`}
                >
                  <p
                    className={`text-sm font-semibold ${
                      (takeover.riskyCount as number) > 0 ? "text-danger" : "text-success"
                    }`}
                  >
                    {(takeover.riskyCount as number) > 0
                      ? `${takeover.riskyCount} host(s) — high-confidence takeover-style signal (DNS or body fingerprint)`
                      : "No high-confidence takeover signals on tested hosts"}
                  </p>
                  <p className="text-text-muted mt-1 leading-relaxed text-[11px]">
                    {(takeover.riskyCount as number) > 0
                      ? "Confirm in DNS + cloud console before changes. False positives can happen."
                      : "Re-scan after DNS changes; automation cannot prove absence of risk everywhere."}
                  </p>
                  {Array.isArray(takeover.hostsScanned) && (
                    <p className="text-[10px] text-text-dim mt-2">
                      Hosts scanned: <span className="font-mono text-text-muted">{(takeover.hostsScanned as string[]).length}</span>
                      {typeof takeover.maxHostsCap === "number" ? ` (max ${takeover.maxHostsCap})` : ""}
                    </p>
                  )}
                </div>
                {isQuickTakeoverOnly && (
                  <p className="text-[11px] text-warning/90 bg-warning/10 border border-warning/25 rounded-lg px-3 py-2">
                    Only the primary domain was checked automatically. Click the button above to include all discovered subdomains (up to 150).
                  </p>
                )}
                {Array.isArray(takeover.risky) && (takeover.risky as unknown[]).length > 0 ? (
                  <div className="space-y-2">
                    {(takeover.risky as {
                      host: string;
                      cname: string | null;
                      service: string | null;
                      detail: string;
                      signal?: string;
                    }[]).map((r, i) => (
                      <div key={i} className="p-3 rounded-lg bg-danger/15 border border-danger/40">
                        <div className="flex flex-wrap items-center gap-2 mb-1">
                          <span className="font-mono text-danger font-semibold text-sm">{r.host}</span>
                          {r.signal === "dns_dangling" ? (
                            <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-danger/30 text-danger border border-danger/40">
                              DNS / NXDOMAIN
                            </span>
                          ) : (
                            <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-danger/30 text-danger border border-danger/40">
                              Body / SaaS fingerprint
                            </span>
                          )}
                          <a
                            href={`https://${r.host}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-0.5 text-[10px] text-accent hover:underline ml-auto"
                          >
                            Open
                            <ArrowUpRight className="w-3 h-3" />
                          </a>
                        </div>
                        <p className="text-text-muted mt-1 leading-relaxed">{r.detail}</p>
                        {r.cname && <p className="font-mono text-[10px] text-text-dim mt-1">CNAME → {r.cname}</p>}
                        {r.service && <p className="text-[10px] text-text-dim">Service: {r.service}</p>}
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            </Panel>
          </div>
        )}

        {/* Ports */}
        {ports && !("error" in ports) && (
          <Panel title="Port & Service Scan" icon={Radio} count={ports.ports.length}>
            <div className="p-4 space-y-3">
              <div className="text-xs text-text-dim mb-2">
                IP: <span className="font-mono text-white">{ports.ip}</span>
                {ports.totalVulns > 0 && (
                  <span className="ml-3 text-danger">{ports.totalVulns} known CVEs</span>
                )}
              </div>
              {(ports.highRiskOpenPortsCount ?? 0) > 0 && (
                <div className="p-3 rounded-lg bg-danger/10 border border-danger/30 text-xs text-danger">
                  <strong>{ports.highRiskOpenPortsCount}</strong> high/critical-risk service ports exposed (Telnet, SMB, RDP, Redis, MongoDB, etc.). Verify firewall scope and authentication.
                </div>
              )}
              {ports.ports.length > 0 ? (
                <div className="space-y-1">
                  {ports.ports.map((p, i) => (
                    <div key={i} className="flex items-center gap-3 bg-bg rounded-lg px-3 py-2 flex-wrap">
                      <span className="font-mono text-sm text-accent font-bold w-16">{p.port}</span>
                      <span className="text-sm text-white flex-1 min-w-[120px]">{p.service}</span>
                      {"exposureRisk" in p && p.exposureRisk && (
                        <span className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded ${
                          p.exposureRisk === "critical" ? "bg-red-500/20 text-red-400" :
                          p.exposureRisk === "high" ? "bg-orange-500/20 text-orange-400" :
                          "bg-yellow-500/20 text-yellow-400"
                        }`}>
                          {p.exposureRisk}
                        </span>
                      )}
                      {"exposureReason" in p && p.exposureReason && (
                        <span className="text-[10px] text-text-dim w-full sm:w-auto">{p.exposureReason}</span>
                      )}
                      {p.product && <span className="text-xs text-text-dim font-mono">{p.product} {p.version || ""}</span>}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-text-muted">No open ports found in Shodan InternetDB.</p>
              )}
              {ports.cves && ports.cves.length > 0 && (
                <div>
                  <div className="text-xs text-text-dim uppercase tracking-wider mt-3 mb-2">Known Vulnerabilities</div>
                  <div className="flex flex-wrap gap-1.5">
                    {ports.cves.slice(0, 20).map((cve, i) => (
                      <a key={i} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                        className="text-[11px] font-mono px-2 py-0.5 rounded bg-danger/10 text-danger hover:bg-danger/20 transition-colors">
                        {cve}
                      </a>
                    ))}
                  </div>
                </div>
              )}
              {ports.tags && ports.tags.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {ports.tags.map((tag, i) => (
                    <span key={i} className="text-[11px] font-mono px-2 py-0.5 rounded bg-warning/10 text-warning">{tag}</span>
                  ))}
                </div>
              )}
            </div>
          </Panel>
        )}

        {/* Technologies */}
        {scan.technologies.length > 0 && (
          <Panel title="Technology Fingerprinting" icon={Cpu} count={scan.technologies.length}>
            <div className="p-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {scan.technologies.map((t, i) => (
                  <div key={i} className="flex items-center gap-3 bg-bg rounded-lg px-3 py-2.5">
                    <div className="w-8 h-8 rounded bg-accent/10 flex items-center justify-center text-accent font-bold text-xs">
                      {t.name.charAt(0)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-white truncate">{t.name}</div>
                      <div className="text-[11px] text-text-dim">{t.category}{t.version ? ` · v${t.version}` : ""}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Panel>
        )}

        {/* Cookies */}
        {scan.cookies.length > 0 && (
          <Panel title="Cookie Security" icon={Cookie} count={scan.cookies.length}>
            <div className="divide-y divide-border">
              {scan.cookies.map((c, i) => (
                <div key={i} className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-mono text-sm text-white">{c.name}</span>
                    <span className="text-[10px] text-text-dim">Path: {c.path}</span>
                  </div>
                  <div className="flex gap-2 mb-2">
                    <span className={`text-[11px] px-1.5 py-0.5 rounded ${c.httpOnly ? "bg-success/10 text-success" : "bg-danger/10 text-danger"}`}>
                      HttpOnly: {c.httpOnly ? "Yes" : "No"}
                    </span>
                    <span className={`text-[11px] px-1.5 py-0.5 rounded ${c.secure ? "bg-success/10 text-success" : "bg-danger/10 text-danger"}`}>
                      Secure: {c.secure ? "Yes" : "No"}
                    </span>
                    <span className={`text-[11px] px-1.5 py-0.5 rounded ${
                      c.sameSite.toLowerCase() === "strict" ? "bg-success/10 text-success" :
                      c.sameSite.toLowerCase() === "lax" ? "bg-warning/10 text-warning" :
                      "bg-danger/10 text-danger"
                    }`}>
                      SameSite: {c.sameSite}
                    </span>
                  </div>
                  {c.issues.map((issue, j) => (
                    <div key={j} className="text-xs text-danger flex items-start gap-1.5 mt-1">
                      <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
                      {issue}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </Panel>
        )}
      </div>

      {virustotal && typeof virustotal === "object" && (
        <Panel title="VirusTotal domain intel" icon={Bug} defaultOpen>
          <div className="p-4 text-xs space-y-3">
            {virustotal.skipped ? (
              <p className="text-text-muted">{String(virustotal.message || "VirusTotal not configured.")}</p>
            ) : virustotal.error ? (
              <p className="text-warning">{String(virustotal.error)}</p>
            ) : (
              <>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm text-white">
                    Domain: <span className="font-mono text-accent">{String(virustotal.domain)}</span>
                  </p>
                  <a
                    href={`https://www.virustotal.com/gui/domain/${encodeURIComponent(String(virustotal.domain))}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-[11px] font-semibold text-accent hover:underline"
                  >
                    Open in VirusTotal
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </a>
                </div>

                {virustotal.analysis && typeof virustotal.analysis === "object" && (virustotal.analysis as { stats?: Record<string, number> }).stats ? (
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {(() => {
                      const st = (virustotal.analysis as { stats: Record<string, number> }).stats;
                      const cells: { k: string; v: number | string }[] = [
                        { k: "URLs (sample)", v: st.detectedUrlsSampled ?? 0 },
                        { k: "URLs w/ positives", v: st.urlsWithPositives ?? 0 },
                        { k: "Max engines / URL", v: st.maxPositivesOnUrl ?? 0 },
                        { k: "Subdomains listed", v: st.subdomainCountListed ?? 0 },
                        { k: "Comm. samples", v: st.communicatingSamples ?? 0 },
                        { k: "Comm. w/ positives", v: st.communicatingWithPositives ?? 0 },
                        { k: "DL samples", v: st.downloadedSamples ?? 0 },
                        { k: "DL w/ positives", v: st.downloadedWithPositives ?? 0 },
                      ];
                      return cells.map((c) => (
                        <div key={c.k} className="rounded-lg border border-border bg-bg/60 px-2 py-2">
                          <div className="text-[9px] uppercase tracking-wider text-text-dim leading-tight">{c.k}</div>
                          <div className="text-lg font-mono text-white mt-0.5">{c.v}</div>
                        </div>
                      ));
                    })()}
                  </div>
                ) : null}

                {virustotal.analysis && typeof virustotal.analysis === "object" && (virustotal.analysis as { concerns?: unknown[] }).concerns
                  && Array.isArray((virustotal.analysis as { concerns: unknown[] }).concerns)
                  ? (() => {
                      const all = (virustotal.analysis as { concerns: { title: string; detail: string; severity: string }[] }).concerns;
                      const primary = all.filter((c) => c.severity !== "info");
                      const informational = all.filter((c) => c.severity === "info");
                      return (
                        <>
                          {primary.length > 0 ? (
                            <div className="rounded-lg border border-border bg-bg/40 divide-y divide-border">
                              <div className="px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-text-dim">
                                Findings (elevated)
                              </div>
                              {primary.map((c, i) => (
                                <div key={i} className="px-3 py-2 text-xs">
                                  <span
                                    className={`font-semibold ${
                                      c.severity === "high"
                                        ? "text-danger"
                                        : c.severity === "medium"
                                          ? "text-warning"
                                          : "text-text-muted"
                                    }`}
                                  >
                                    {c.title}
                                  </span>
                                  <p className="text-text-dim mt-0.5 leading-relaxed">{c.detail}</p>
                                </div>
                              ))}
                            </div>
                          ) : null}
                          {informational.length > 0 ? (
                            <details className="rounded-lg border border-border/60 bg-bg/20 text-[11px] text-text-dim">
                              <summary className="cursor-pointer px-3 py-2 font-medium text-text-muted">
                                Additional context ({informational.length})
                              </summary>
                              <div className="px-3 pb-2 space-y-2 border-t border-border/40 pt-2">
                                {informational.map((c, i) => (
                                  <div key={i}>
                                    <span className="font-semibold text-text-muted">{c.title}</span>
                                    <p className="mt-0.5 leading-relaxed">{c.detail}</p>
                                  </div>
                                ))}
                              </div>
                            </details>
                          ) : null}
                        </>
                      );
                    })()
                  : null}

                {virustotal.analysis && typeof virustotal.analysis === "object" && (virustotal.analysis as { novice?: unknown }).novice ? (
                  (() => {
                    const nov = (virustotal.analysis as {
                      novice: {
                        level: string;
                        title: string;
                        subtitle: string;
                        explanation: string;
                        bullets: string[];
                        whatNow: string;
                      };
                    }).novice;
                    const ring =
                      nov.level === "red"
                        ? "border-danger/50 bg-danger/10"
                        : nov.level === "amber"
                          ? "border-warning/50 bg-warning/10"
                          : "border-success/40 bg-success/5";
                    return (
                      <div className={`rounded-xl border p-4 space-y-3 ${ring}`}>
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                              nov.level === "red"
                                ? "bg-danger/30 text-danger"
                                : nov.level === "amber"
                                  ? "bg-warning/30 text-warning"
                                  : "bg-success/20 text-success"
                            }`}
                          >
                            {nov.level === "red" ? "Higher priority" : nov.level === "amber" ? "Worth a look" : "Looks OK in this snapshot"}
                          </span>
                        </div>
                        <h4 className="text-base font-semibold text-white leading-snug">{nov.title}</h4>
                        <p className="text-sm text-text-muted">{nov.subtitle}</p>
                        <p className="text-sm text-text-muted leading-relaxed">{nov.explanation}</p>
                        {nov.bullets?.length > 0 && (
                          <ul className="text-sm text-text-muted space-y-1.5 list-disc pl-4">
                            {nov.bullets.map((b, i) => (
                              <li key={i}>{b}</li>
                            ))}
                          </ul>
                        )}
                        <div className="rounded-lg bg-bg/80 border border-border px-3 py-2 text-sm text-accent">
                          <span className="text-text-dim text-xs uppercase tracking-wider">What you can do</span>
                          <p className="text-text-muted mt-1 leading-relaxed">{nov.whatNow}</p>
                        </div>
                      </div>
                    );
                  })()
                ) : null}

                <details className="vt-analyst-disclosure rounded-lg border border-border bg-bg/40">
                  <summary className="cursor-pointer px-3 py-2 text-xs text-text-muted list-none flex items-center gap-2 marker:content-none">
                    <ChevronRight className="vt-analyst-disclosure-chevron w-3.5 h-3.5 shrink-0 transition-transform duration-200" />
                    Full VT export (single JSON — copy / verify in VirusTotal GUI)
                  </summary>
                  <div className="px-3 pb-3 pt-0 border-t border-border space-y-2 text-[11px] text-text-dim">
                    <p className="leading-relaxed">
                      One consolidated object from the domain report (larger limits than the summary cards). Use this to
                      manually cross-check hashes, URLs, and WHOIS without fragmented blocks.
                    </p>
                    <button
                      type="button"
                      onClick={() => setVtShowRaw((v) => !v)}
                      className="text-accent hover:underline font-semibold"
                    >
                      {vtShowRaw ? "Hide JSON" : "Show full JSON"}
                    </button>
                    {vtShowRaw && vtExportPayload ? (
                      <pre className="font-mono text-[10px] text-text-muted whitespace-pre-wrap break-all border border-border rounded-lg p-3 bg-bg max-h-[28rem] overflow-y-auto">
                        {JSON.stringify(vtExportPayload, null, 2)}
                      </pre>
                    ) : null}
                  </div>
                </details>

                <p className="text-text-dim text-[10px]">
                  Use VirusTotal only on domains you are allowed to check, per their Terms of Service.
                </p>
              </>
            )}
          </div>
        </Panel>
      )}

      {wpCron && typeof wpCron === "object" && !("error" in wpCron) && (
        <Panel
          title="WP cron & infra exposure"
          icon={Timer}
          count={
            (Array.isArray(wpCron.infraChecks)
              ? (wpCron.infraChecks as { exposed: boolean }[]).filter((x) => x.exposed).length
              : 0) +
            (Array.isArray(wpCron.checks)
              ? (wpCron.checks as { exposed: boolean }[]).filter((x) => x.exposed).length
              : 0)
          }
          defaultOpen
        >
          <div className="p-4 text-xs space-y-3">
            <p className="text-text-dim leading-relaxed">
              <span className="text-text-muted font-semibold">WordPress:</span> Nuclei-style{" "}
              <code className="text-text-muted">/wp-cron.php</code>, <code className="text-text-muted">/wp/wp-cron.php</code>{" "}
              (CVE-2023-22622).{" "}
              <span className="text-text-muted font-semibold">Infra:</span> Swagger/OpenAPI, Java heapdump, Spring Actuator,
              Prometheus <code className="text-text-muted">/metrics</code> (heuristic matchers; verify manually).
            </p>
            {Array.isArray(wpCron.checks) &&
              (wpCron.checks as { path: string; status: number; exposed: boolean; matcher: string; recommendation: string; category?: string }[]).map((c, i) => (
                <div key={`wp-${i}`} className={`p-2 rounded border ${c.exposed ? "border-warning/40 bg-warning/5" : "border-border bg-bg"}`}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] uppercase text-text-dim">wp-cron</span>
                    <span className="font-mono text-white">{c.path}</span>
                    <span className="text-text-dim">HTTP {c.status}</span>
                    <span className={c.exposed ? "text-warning font-medium" : "text-success"}>{c.exposed ? "Pattern match" : "No Nuclei match"}</span>
                    <span className="text-text-dim">({c.matcher})</span>
                  </div>
                  <p className="text-text-muted mt-1">{c.recommendation}</p>
                </div>
              ))}
            {Array.isArray(wpCron.infraChecks) && (wpCron.infraChecks as { category: string }[]).length > 0 ? (
              <div className="space-y-2 pt-1 border-t border-border/80">
                <div className="text-[10px] uppercase text-text-dim font-semibold">Swagger / heapdump / Actuator / Prometheus</div>
                {(wpCron.infraChecks as {
                  path: string;
                  category: string;
                  status: number;
                  bodyLength: number;
                  exposed: boolean;
                  matcher: string;
                  severity: string;
                  recommendation: string;
                }[]).map((c, i) => (
                  <div
                    key={`infra-${i}`}
                    className={`p-2 rounded border ${
                      c.exposed
                        ? c.severity === "critical"
                          ? "border-danger/50 bg-danger/5"
                          : c.severity === "high"
                            ? "border-orange-500/40 bg-orange-500/5"
                            : "border-warning/40 bg-warning/5"
                        : "border-border bg-bg"
                    }`}
                  >
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-bg border border-border text-text-muted">{c.category}</span>
                      <span className="font-mono text-white">{c.path}</span>
                      <span className="text-text-dim">HTTP {c.status}</span>
                      <span className={c.exposed ? "text-warning font-medium" : "text-success"}>
                        {c.exposed ? `Match (${c.matcher})` : "No match"}
                      </span>
                      {c.exposed ? <span className="text-[10px] text-text-dim">sev: {c.severity}</span> : null}
                    </div>
                    <p className="text-text-muted mt-1">{c.recommendation}</p>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        </Panel>
      )}

      {googleDork && typeof googleDork === "object" && !("error" in googleDork) && (
        <Panel
          title="Google dork reconnaissance"
          icon={Search}
          count={Array.isArray(googleDork.hits) ? (googleDork.hits as unknown[]).length : 0}
          defaultOpen
        >
          <div className="p-4 text-xs space-y-3">
            <p className="text-text-dim leading-relaxed">
              {(googleDork as { note?: string }).note}
            </p>
            {(googleDork as { mode?: string }).mode === "manual" ? (
              <p className="text-[11px] text-warning/90 border border-warning/30 rounded-lg px-3 py-2 bg-warning/5">
                Automated hits need <code className="text-text-muted">GOOGLE_CSE_API_KEY</code> +{" "}
                <code className="text-text-muted">GOOGLE_CSE_ID</code> in <code className="text-text-muted">.env.local</code>. Use
                the links below only for authorized targets.
              </p>
            ) : null}
            {Array.isArray(googleDork.hits) && (googleDork.hits as unknown[]).length > 0 ? (
              <div className="space-y-2 max-h-72 overflow-y-auto">
                <div className="text-[10px] uppercase text-text-dim font-semibold">Indexed URL hits (API)</div>
                {(googleDork.hits as { title: string; link: string; snippet?: string; dorkTitle: string }[]).map((h, i) => (
                  <div key={i} className="p-2 rounded border border-border bg-bg space-y-1">
                    <div className="text-[10px] text-text-dim">{h.dorkTitle}</div>
                    <a href={h.link} target="_blank" rel="noopener noreferrer" className="text-sm text-accent font-medium hover:underline break-all">
                      {h.title}
                    </a>
                    <p className="text-text-muted text-[11px] leading-relaxed">{h.snippet}</p>
                    <p className="font-mono text-[10px] text-text-dim break-all">{h.link}</p>
                  </div>
                ))}
              </div>
            ) : (googleDork as { mode?: string }).mode === "api" ? (
              <p className="text-success">No result items returned for the configured dork queries (or quota empty).</p>
            ) : null}
            {Array.isArray((googleDork as { manualQueries?: unknown[] }).manualQueries) ? (
              <div className="space-y-2 pt-2 border-t border-border/80">
                <div className="text-[10px] uppercase text-text-dim font-semibold">Dork queries (open in Google)</div>
                <div className="max-h-64 overflow-y-auto space-y-2">
                  {(
                    googleDork.manualQueries as {
                      id: string;
                      title: string;
                      description: string;
                      query: string;
                      googleUrl: string;
                    }[]
                  ).map((q) => (
                    <div key={q.id} className="p-2 rounded border border-border/80 bg-surface-2/20">
                      <div className="font-medium text-white">{q.title}</div>
                      <p className="text-text-dim text-[11px] mt-0.5">{q.description}</p>
                      <p className="font-mono text-[10px] text-text-muted mt-1 break-all">{q.query}</p>
                      <a
                        href={q.googleUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 mt-2 text-accent text-[11px] font-semibold hover:underline"
                      >
                        Search on Google <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            {Array.isArray((googleDork as { apiErrors?: string[] }).apiErrors) && (googleDork as { apiErrors: string[] }).apiErrors!.length > 0 ? (
              <div className="text-[11px] text-danger space-y-1">
                {(googleDork as { apiErrors: string[] }).apiErrors!.map((e, i) => (
                  <p key={i}>{e}</p>
                ))}
              </div>
            ) : null}
          </div>
        </Panel>
      )}

      {/* AI Report - Full Width */}
      {ai && !("error" in ai) && (
        <Panel title="AI Security Assessment" icon={Brain} defaultOpen>
          <div className="p-6 space-y-5">
            <div className="flex items-center gap-3">
              <span className={`text-sm font-semibold px-3 py-1 rounded-lg ${
                ai.riskLevel === "Critical" ? "bg-red-500/15 text-red-400" :
                ai.riskLevel === "High" ? "bg-orange-500/15 text-orange-400" :
                ai.riskLevel === "Medium" ? "bg-yellow-500/15 text-yellow-400" :
                "bg-green-500/15 text-green-400"
              }`}>
                Risk: {ai.riskLevel}
              </span>
            </div>

            <div>
              <h4 className="text-xs text-text-dim uppercase tracking-wider mb-2">Executive Summary</h4>
              <p className="text-sm text-text-muted leading-relaxed">{ai.executiveSummary}</p>
            </div>

            <div>
              <h4 className="text-xs text-text-dim uppercase tracking-wider mb-2">Top Findings</h4>
              <ol className="space-y-1.5">
                {ai.topFindings.map((f, i) => (
                  <li key={i} className="text-sm text-text-muted flex items-start gap-2">
                    <span className="text-accent font-mono font-bold shrink-0">{i + 1}.</span>
                    {f}
                  </li>
                ))}
              </ol>
            </div>

            <div>
              <h4 className="text-xs text-text-dim uppercase tracking-wider mb-2">Recommendations</h4>
              <ul className="space-y-1.5">
                {ai.recommendations.map((r, i) => (
                  <li key={i} className="text-sm text-text-muted flex items-start gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-success mt-0.5 shrink-0" />
                    {r}
                  </li>
                ))}
              </ul>
            </div>

            {ai.complianceNotes.length > 0 && (
              <div>
                <h4 className="text-xs text-text-dim uppercase tracking-wider mb-2">Compliance Notes</h4>
                <ul className="space-y-1">
                  {ai.complianceNotes.map((n, i) => (
                    <li key={i} className="text-xs text-text-dim flex items-start gap-2">
                      <FileText className="w-3 h-3 mt-0.5 shrink-0" />
                      {n}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Panel>
      )}
    </div>
  );
}
