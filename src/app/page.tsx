"use client";
import { useState, useCallback, useRef, useEffect } from "react";
import { Shield, Code2, Scan, Activity, Globe, Mail } from "lucide-react";
import Header from "@/components/Header";
import ScanForm from "@/components/ScanForm";
import ScanProgress, { type ModuleProgress } from "@/components/ScanProgress";
import ResultsDashboard from "@/components/ResultsDashboard";
import ToolsWorkspace from "@/components/ToolsWorkspace";
import ScanHistoryCompare from "@/components/ScanHistoryCompare";
import ScanUnreachableDialog from "@/components/ScanUnreachableDialog";
import { useI18n } from "@/components/I18nProvider";
import type { ScanResult, SSLResult, PortScanResult, AIReport } from "@/lib/types";
import { normalizeTarget } from "@/lib/utils";
import { jsonHeadersWithArgus } from "@/lib/argus-client-headers";
import { pushScanHistory } from "@/lib/scan-history-local";
import { modulesForProgress, shouldRunModule, type ScanPreset } from "@/lib/scan-presets";
import type { MailAuthResult, SiteMetaResult } from "@/lib/mail-site-types";

type Tab = "scanner" | "workspace";

type FetchModuleResult =
  | { ok: true }
  | { ok: false; unreachable?: { title: string; detail: string }; cancelled?: boolean };

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

export default function Home() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>("scanner");
  const [scanPreset, setScanPreset] = useState<ScanPreset>("complete");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState<ModuleProgress[]>([]);
  const [results, setResults] = useState<AllResults | null>(null);
  const [historyRev, setHistoryRev] = useState(0);
  const [unreachableDialog, setUnreachableDialog] = useState<{
    title: string;
    detail: string;
    target: string;
  } | null>(null);
  const abortScanRef = useRef<AbortController | null>(null);
  const lastTargetRef = useRef("");
  const accumulatedRef = useRef<AllResults>({});

  useEffect(() => {
    if (results) accumulatedRef.current = results;
  }, [results]);

  const updateModule = useCallback((id: string, status: ModuleProgress["status"], error?: string) => {
    setProgress((prev) =>
      prev.map((m) => (m.id === id ? { ...m, status, error } : m))
    );
  }, []);

  const fetchModule = useCallback(
    async (
      id: string,
      endpoint: string,
      body: Record<string, unknown>,
      signal: AbortSignal,
      onSuccess: (data: unknown) => void,
    ): Promise<FetchModuleResult> => {
      updateModule(id, "running");
      try {
        const res = await fetch(endpoint, {
          method: "POST",
          headers: jsonHeadersWithArgus(),
          body: JSON.stringify(body),
          signal,
        });
        const text = await res.text();
        let data: unknown = {};
        if (text.trim()) {
          try {
            data = JSON.parse(text) as unknown;
          } catch {
            updateModule(id, "error", `HTTP ${res.status} — invalid response`);
            return { ok: false };
          }
        }
        const d = data as {
          error?: string;
          skipped?: boolean;
          unreachable?: boolean;
          title?: string;
          detail?: string;
        };
        if (!res.ok) {
          if (d.unreachable === true && typeof d.title === "string") {
            const detail = typeof d.detail === "string" ? d.detail : "";
            updateModule(id, "error", typeof d.error === "string" ? d.error : d.title);
            return { ok: false, unreachable: { title: d.title, detail } };
          }
          updateModule(id, "error", d.error || `HTTP ${res.status}`);
          return { ok: false };
        }
        if (d.error && d.skipped !== true && id !== "virustotal") {
          updateModule(id, "error", String(d.error));
          return { ok: false };
        }
        onSuccess(data);
        updateModule(id, "done");
        return { ok: true };
      } catch (e: unknown) {
        if (e instanceof Error && e.name === "AbortError") {
          updateModule(id, "error", "Canceled");
          return { ok: false, cancelled: true };
        }
        updateModule(id, "error", e instanceof Error ? e.message : "Network error");
        return { ok: false };
      }
    },
    [updateModule],
  );

  const cancelScan = useCallback(() => {
    abortScanRef.current?.abort();
  }, []);

  const runScan = useCallback(
    async (target: string) => {
      const ac = new AbortController();
      abortScanRef.current = ac;
      lastTargetRef.current = target;
      setScanning(true);
      setResults(null);
      const inc = (id: string) => shouldRunModule(scanPreset, id);
      setProgress(modulesForProgress(scanPreset).map((m) => ({ ...m, status: "pending" as const })));

      const accumulated: AllResults = {};
      accumulatedRef.current = accumulated;

      let skipResultsForUnreachable = false;
      let unreachableBanner: { title: string; detail: string; target: string } | null = null;

      try {
        const headerResult = await fetchModule("headers", "/api/scan", { url: target }, ac.signal, (data) => {
          accumulated.scan = data as ScanResult;
          updateModule("tech", "done");
        });

        if (!headerResult.ok && headerResult.unreachable) {
          const ur = headerResult.unreachable;
          ac.abort();
          setProgress((prev) =>
            prev.map((m) =>
              m.id === "headers"
                ? { ...m, status: "error" as const, error: ur.title }
                : { ...m, status: "skipped" as const, error: "Target unreachable — skipped" },
            ),
          );
          skipResultsForUnreachable = true;
          unreachableBanner = { title: ur.title, detail: ur.detail, target };
          return;
        }

        const parallel: Promise<FetchModuleResult>[] = [];
        if (inc("source")) {
          parallel.push(
            fetchModule("source", "/api/source-audit", { url: target }, ac.signal, (data) => {
              accumulated.sourceAudit = data as AllResults["sourceAudit"];
            }),
          );
        }
        if (inc("ssl")) {
          parallel.push(
            fetchModule("ssl", "/api/ssl", { url: target }, ac.signal, (data) => {
              accumulated.ssl = data as SSLResult;
            }),
          );
        }
        if (inc("mailAuth")) {
          parallel.push(
            fetchModule("mailAuth", "/api/mail-auth", { url: target }, ac.signal, (data) => {
              accumulated.mailAuth = data as MailAuthResult;
            }),
          );
        }
        if (inc("siteMeta")) {
          parallel.push(
            fetchModule("siteMeta", "/api/site-meta", { url: target }, ac.signal, (data) => {
              accumulated.siteMeta = data as SiteMetaResult;
            }),
          );
        }
        if (inc("subdomains")) {
          parallel.push(
            fetchModule("subdomains", "/api/subdomains", { url: target }, ac.signal, (data) => {
              accumulated.subdomains = data as AllResults["subdomains"];
            }),
          );
        }
        if (inc("ports")) {
          parallel.push(
            fetchModule("ports", "/api/ports", { url: target }, ac.signal, (data) => {
              accumulated.ports = data as AllResults["ports"];
            }),
          );
        }
        if (inc("virustotal")) {
          parallel.push(
            fetchModule("virustotal", "/api/virustotal", { url: target }, ac.signal, (data) => {
              accumulated.virustotal = data as AllResults["virustotal"];
            }),
          );
        }
        if (inc("wpcron")) {
          parallel.push(
            fetchModule("wpcron", "/api/wordpress-wpcron", { url: target }, ac.signal, (data) => {
              accumulated.wpCron = data as AllResults["wpCron"];
            }),
          );
        }
        if (inc("googleDork")) {
          parallel.push(
            fetchModule("googleDork", "/api/google-dork", { url: target }, ac.signal, (data) => {
              accumulated.googleDork = data as AllResults["googleDork"];
            }),
          );
        }
        await Promise.all(parallel);

        if (inc("takeover")) {
          const apex = accumulated.scan?.target.hostname ?? normalizeTarget(target).hostname;
          await fetchModule("takeover", "/api/takeover-scan", { hosts: [apex], maxHosts: 5 }, ac.signal, (data) => {
            accumulated.takeover = data as AllResults["takeover"];
          });
        }

        if (inc("ai")) {
          if (accumulated.scan) {
            await fetchModule("ai", "/api/ai-report", {
              scanData: {
                target: accumulated.scan.target.hostname,
                headers: accumulated.scan.headers,
                score: accumulated.scan.score,
                grade: accumulated.scan.grade,
                cookies: accumulated.scan.cookies,
                technologies: accumulated.scan.technologies,
                ssl: accumulated.ssl,
                ports: accumulated.ports,
                sourceAuditSummary: accumulated.sourceAudit?.summary,
                secretFindingsCount: Array.isArray(accumulated.sourceAudit?.secretFindings)
                  ? (accumulated.sourceAudit.secretFindings as unknown[]).length
                  : 0,
                libraryRisks: accumulated.sourceAudit?.libraryRisks,
                takeoverRiskyCount: accumulated.takeover?.riskyCount,
                virusTotal: accumulated.virustotal?.skipped ? "skipped" : accumulated.virustotal,
                wpCron: accumulated.wpCron,
              },
            }, ac.signal, (data) => {
              accumulated.ai = data as AIReport;
            });
          } else {
            updateModule("ai", "error", "Skipped — no scan data");
          }
        }
      } finally {
        if (abortScanRef.current === ac) abortScanRef.current = null;
        accumulatedRef.current = accumulated;
        if (skipResultsForUnreachable) {
          setResults(null);
          if (unreachableBanner) setUnreachableDialog(unreachableBanner);
        } else {
          setResults({ ...accumulated });
        }
        setScanning(false);
        if (!ac.signal.aborted) {
          try {
            pushScanHistory({
              target,
              label: `${target} (${scanPreset})`,
              snapshot: JSON.parse(JSON.stringify(accumulated)) as Record<string, unknown>,
            });
            setHistoryRev((n) => n + 1);
          } catch {
            /* ignore */
          }
        }
      }
    },
    [fetchModule, updateModule, scanPreset],
  );

  const retryModule = useCallback(
    async (id: string) => {
      const target = lastTargetRef.current;
      if (!target) return;
      const acc = { ...accumulatedRef.current };
      const signal = AbortSignal.timeout(300_000);

      const scanDataBody =
        acc.scan
          ? {
              target: acc.scan.target.hostname,
              headers: acc.scan.headers,
              score: acc.scan.score,
              grade: acc.scan.grade,
              cookies: acc.scan.cookies,
              technologies: acc.scan.technologies,
              ssl: acc.ssl,
              ports: acc.ports,
              sourceAuditSummary: acc.sourceAudit?.summary,
              secretFindingsCount: Array.isArray(acc.sourceAudit?.secretFindings)
                ? (acc.sourceAudit.secretFindings as unknown[]).length
                : 0,
              libraryRisks: acc.sourceAudit?.libraryRisks,
              takeoverRiskyCount: acc.takeover?.riskyCount,
              virusTotal: acc.virustotal?.skipped ? "skipped" : acc.virustotal,
              wpCron: acc.wpCron,
            }
          : null;

      switch (id) {
        case "headers":
        case "tech":
          await fetchModule("headers", "/api/scan", { url: target }, signal, (data) => {
            acc.scan = data as ScanResult;
            updateModule("tech", "done");
          });
          break;
        case "source":
          await fetchModule("source", "/api/source-audit", { url: target }, signal, (data) => {
            acc.sourceAudit = data as AllResults["sourceAudit"];
          });
          break;
        case "ssl":
          await fetchModule("ssl", "/api/ssl", { url: target }, signal, (data) => {
            acc.ssl = data as SSLResult;
          });
          break;
        case "subdomains":
          await fetchModule("subdomains", "/api/subdomains", { url: target }, signal, (data) => {
            acc.subdomains = data as AllResults["subdomains"];
          });
          break;
        case "ports":
          await fetchModule("ports", "/api/ports", { url: target }, signal, (data) => {
            acc.ports = data as AllResults["ports"];
          });
          break;
        case "virustotal":
          await fetchModule("virustotal", "/api/virustotal", { url: target }, signal, (data) => {
            acc.virustotal = data as AllResults["virustotal"];
          });
          break;
        case "wpcron":
          await fetchModule("wpcron", "/api/wordpress-wpcron", { url: target }, signal, (data) => {
            acc.wpCron = data as AllResults["wpCron"];
          });
          break;
        case "googleDork":
          await fetchModule("googleDork", "/api/google-dork", { url: target }, signal, (data) => {
            acc.googleDork = data as AllResults["googleDork"];
          });
          break;
        case "mailAuth":
          await fetchModule("mailAuth", "/api/mail-auth", { url: target }, signal, (data) => {
            acc.mailAuth = data as MailAuthResult;
          });
          break;
        case "siteMeta":
          await fetchModule("siteMeta", "/api/site-meta", { url: target }, signal, (data) => {
            acc.siteMeta = data as SiteMetaResult;
          });
          break;
        case "takeover": {
          const apex = acc.scan?.target.hostname ?? normalizeTarget(target).hostname;
          await fetchModule("takeover", "/api/takeover-scan", { hosts: [apex], maxHosts: 5 }, signal, (data) => {
            acc.takeover = data as AllResults["takeover"];
          });
          break;
        }
        case "ai":
          if (scanDataBody) {
            await fetchModule("ai", "/api/ai-report", { scanData: scanDataBody }, signal, (data) => {
              acc.ai = data as AIReport;
            });
          } else {
            updateModule("ai", "error", "No scan data");
          }
          break;
        default:
          break;
      }

      accumulatedRef.current = acc;
      setResults({ ...acc });
    },
    [fetchModule, updateModule],
  );

  return (
    <div className="min-h-screen flex flex-col">
      {unreachableDialog && (
        <ScanUnreachableDialog
          title={unreachableDialog.title}
          detail={unreachableDialog.detail}
          target={unreachableDialog.target}
          onClose={() => setUnreachableDialog(null)}
        />
      )}
      <Header />

      <div className="border-b border-border bg-surface/40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex gap-1">
          <button
            onClick={() => setTab("scanner")}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              tab === "scanner"
                ? "border-accent text-accent"
                : "border-transparent text-text-muted hover:text-white"
            }`}
          >
            <Scan className="w-4 h-4" />
            {t("nav.scanner")}
          </button>
          <button
            onClick={() => setTab("workspace")}
            className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              tab === "workspace"
                ? "border-accent text-accent"
                : "border-transparent text-text-muted hover:text-white"
            }`}
          >
            <Code2 className="w-4 h-4" />
            {t("nav.workspace")}
          </button>
        </div>
      </div>

      <main className="flex-1">
        {tab === "scanner" && (
          <>
            <ScanForm
              onScan={runScan}
              scanning={scanning}
              scanPreset={scanPreset}
              onPresetChange={setScanPreset}
            />
            <ScanHistoryCompare
              refreshToken={historyRev}
              onRestore={(snapshot, t) => {
                lastTargetRef.current = t;
                const next = snapshot as AllResults;
                accumulatedRef.current = next;
                setResults(next);
              }}
            />
            {scanning && (
              <ScanProgress
                modules={progress}
                presetLabel={scanPreset === "quick" ? t("scanner.presetQuick") : t("scanner.presetComplete")}
                onCancel={cancelScan}
                onRetryModule={(mid) => void retryModule(mid)}
              />
            )}
            {results && !scanning && (
              <ResultsDashboard
                results={results}
                onResultsPatch={(patch) =>
                  setResults((prev) => (prev ? { ...prev, ...patch } : prev))
                }
              />
            )}

            {!results && !scanning && (
              <div className="max-w-5xl mx-auto px-4 pb-16">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                  {(
                    [
                      { icon: Shield, titleKey: "home.featureCards.headers", descKey: "home.featureCards.headersDesc" },
                      { icon: Activity, titleKey: "home.featureCards.source", descKey: "home.featureCards.sourceDesc" },
                      { icon: Scan, titleKey: "home.featureCards.ports", descKey: "home.featureCards.portsDesc" },
                      { icon: Code2, titleKey: "home.featureCards.ai", descKey: "home.featureCards.aiDesc" },
                      { icon: Mail, titleKey: "home.featureCards.mail", descKey: "home.featureCards.mailDesc" },
                      { icon: Globe, titleKey: "home.featureCards.preset", descKey: "home.featureCards.presetDesc" },
                    ] as const
                  ).map((f, i) => (
                    <div
                      key={i}
                      className="bg-surface border border-border rounded-xl p-5 hover:border-border-hover transition-colors animate-fade-up"
                      style={{ animationDelay: `${i * 100}ms` }}
                    >
                      <div className="w-10 h-10 rounded-lg bg-accent/10 flex items-center justify-center mb-3">
                        <f.icon className="w-5 h-5 text-accent" />
                      </div>
                      <h3 className="text-sm font-semibold text-white mb-1">{t(f.titleKey)}</h3>
                      <p className="text-xs text-text-muted">{t(f.descKey)}</p>
                    </div>
                  ))}
                </div>

                <div className="mt-10 text-center">
                  <h3 className="text-sm font-medium text-text-dim mb-4">{t("home.dataSources")}</h3>
                  <div className="flex flex-wrap justify-center gap-4 text-xs text-text-dim font-mono">
                    <span>Shodan InternetDB</span>
                    <span>·</span>
                    <span>crt.sh</span>
                    <span>·</span>
                    <span>VirusTotal (optional)</span>
                    <span>·</span>
                    <span>Node TLS / DNS</span>
                    <span>·</span>
                    <span>Gemini AI (optional)</span>
                  </div>
                </div>
              </div>
            )}
          </>
        )}

        {tab === "workspace" && <ToolsWorkspace />}
      </main>

      <footer className="border-t border-border py-6 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-center sm:justify-between gap-3 text-center sm:text-left">
          <div className="flex flex-col sm:flex-row items-center gap-1 sm:gap-3 text-xs text-text-dim">
            <span className="flex items-center gap-2">
              <Shield className="w-3.5 h-3.5 shrink-0" />
              {t("footer.product")}
            </span>
          </div>
          <div className="flex items-center gap-4 text-xs text-text-dim">
            <a href="https://www.linkedin.com/in/ankits-pandey07/" target="_blank" rel="noopener noreferrer" className="hover:text-[#0A66C2] transition-colors">LinkedIn</a>
            <a href="https://github.com/ankitspandey07" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">GitHub</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
