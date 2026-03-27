"use client";
import { useCallback, useState } from "react";
import { FileJson, FileText, FileDown, Loader2, Copy, Check, Braces } from "lucide-react";
import type { ScanResult, SSLResult, PortScanResult, AIReport } from "@/lib/types";
import type { FetchedMeta, MailAuthResult, SiteMetaResult } from "@/lib/mail-site-types";
import { buildLibraryInventory } from "@/lib/library-inventory";
import { jsonHeadersWithArgus } from "@/lib/argus-client-headers";
import { buildSecuritySarif } from "@/lib/build-sarif";
import { useI18n } from "@/components/I18nProvider";

export interface ReportExporterResults {
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
  mailAuth?: MailAuthResult;
  siteMeta?: SiteMetaResult;
  ai?: AIReport;
}

function csvEscape(s: string): string {
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function buildCsv(r: ReportExporterResults): string {
  const rows: string[][] = [["section", "id", "severity", "title", "description", "impact", "recommendation", "steps_to_reproduce", "poc"]];
  const scan = r.scan;
  if (scan) {
    rows.push(["summary", "score", "", "Security score", `${scan.score}/100 grade ${scan.grade}`, "Aggregate header/cookie posture.", "Review failed/warn items below.", "", ""]);
    for (const h of scan.headers) {
      if (h.status === "pass") continue;
      const impact =
        h.severity === "critical" ? "Critical exposure or missing control." :
        h.severity === "high" ? "High risk to users or data." :
        h.severity === "medium" ? "Medium — defense in depth weakened." : "Low / informational.";
      const steps = `GET https://${scan.target.hostname}/ → DevTools Network → inspect "${h.name}" header.`;
      const poc = `curl -sI "https://${scan.target.hostname}/" | grep -i "${h.name.split("-")[0]}"`;
      rows.push(["header", h.name, h.severity, h.name, h.description, impact, h.remediation, steps, poc]);
    }
    for (const c of scan.cookies) {
      for (const issue of c.issues) {
        rows.push(["cookie", c.name, "medium", `Cookie ${c.name}`, issue, "Session or CSRF risk if exploited with XSS.", "Set HttpOnly, Secure, Strict SameSite as appropriate.", "Inspect Set-Cookie in response.", "Document.cookie in DevTools if not HttpOnly."]);
      }
    }
  }
  if (r.ssl) {
    for (const v of r.ssl.vulnerabilities.filter((x) => x.vulnerable)) {
      rows.push(["ssl", v.name, "high", v.name, v.description, "TLS misconfiguration may enable downgrade or MITM.", "Upgrade protocols/ciphers; renew certificates.", "Run testssl.sh or SSL Labs against host.", "openssl s_client -connect host:443 -tls1"]);
    }
  }
  if (r.ports?.ports?.length) {
    for (const p of r.ports.ports) {
      rows.push([
        "port",
        String(p.port),
        p.exposureRisk || "info",
        `${p.service} :${p.port}`,
        p.exposureReason || "Open port observed via Shodan InternetDB.",
        p.exposureRisk === "critical" || p.exposureRisk === "high" ? "Attack surface for known abuse patterns." : "Verify intent and firewall scope.",
        "Close or firewall; require auth/VPN.",
        `nmap -p ${p.port} ${r.ports.ip}`,
        `telnet ${r.ports.ip} ${p.port} (if allowed)`,
      ]);
    }
  }
  if (r.sourceAudit && Array.isArray(r.sourceAudit.secretFindings)) {
    for (const f of r.sourceAudit.secretFindings as {
      label: string;
      severity: string;
      redacted: string;
      hint: string;
      sourceUrl: string;
      lineNumber?: number;
      columnApprox?: number;
      contextSnippet?: string;
      locateHint?: string;
    }[]) {
      const loc =
        typeof f.lineNumber === "number"
          ? `Line ${f.lineNumber}${typeof f.columnApprox === "number" ? ` (~col ${f.columnApprox})` : ""}`
          : "";
      const description = [
        `${f.redacted} @ ${f.sourceUrl}`,
        loc,
        f.contextSnippet ? `Context (secret removed): ${f.contextSnippet}` : "",
        f.locateHint ? `How to find: ${f.locateHint}` : "",
      ]
        .filter(Boolean)
        .join("\n");
      const steps =
        f.locateHint ||
        `Open ${f.sourceUrl} → View Source or DevTools Sources → search for text shown in context (value redacted in report).`;
      rows.push([
        "secret",
        f.label,
        f.severity,
        f.label,
        description,
        "Secret material may be exposed to clients.",
        f.hint,
        steps,
        "Manual verification only; do not exfiltrate secrets.",
      ]);
    }
  }
  if (r.sourceAudit && Array.isArray(r.sourceAudit.retireMatches)) {
    for (const m of r.sourceAudit.retireMatches as {
      library: string;
      version: string;
      cves: string[];
      summary: string;
      scriptUrl: string;
      detectionSource?: string;
    }[]) {
      const src = m.detectionSource ? ` [${m.detectionSource}]` : "";
      rows.push([
        "library_cve",
        m.library,
        "high",
        `${m.library} ${m.version}${src}`,
        m.summary,
        "Known CVE lineage (Retire.js DB).",
        "Upgrade to patched version.",
        `Load ${m.scriptUrl} and confirm version in path or file.`,
        m.cves.join(", "),
      ]);
    }
  }
  if (r.scan && r.sourceAudit && typeof r.sourceAudit === "object" && !("error" in r.sourceAudit)) {
    const sa = r.sourceAudit as Record<string, unknown>;
    const inv = buildLibraryInventory({
      scan: r.scan,
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
    rows.push([
      "library_summary",
      "counts",
      "info",
      "Library inventory",
      inv.explanation,
      `${inv.passed} pass / ${inv.failed} fail / ${inv.warned} warn`,
      "Upgrade failed; review warned; document passed.",
      "",
      "",
    ]);
    for (const it of inv.items) {
      rows.push([
        "library_item",
        it.id,
        it.status,
        `${it.name}${it.version ? ` v${it.version}` : ""}`,
        it.detail,
        it.status === "fail" ? "CVE or Retire match" : it.status === "warn" ? "Heuristic / EOL risk" : "No automatic CVE match",
        "Verify in dependency scanner / SBOM.",
        it.source,
        it.referenceUrl || "",
      ]);
    }
  }
  if (r.mailAuth) {
    const m = r.mailAuth;
    rows.push(["mail", "mx_count", "info", "MX records", String(m.mx.length), "DNS mail routing.", "Review SPF/DMARC rows.", "", ""]);
    m.mx.forEach((x, i) =>
      rows.push(["mail", `mx_${i}`, "info", x.exchange, `priority ${x.priority}`, "", "", "", ""]),
    );
    if (m.spf) rows.push(["mail", "spf", "info", "SPF", m.spf.record, m.spf.host, "", "", ""]);
    if (m.dmarc) rows.push(["mail", "dmarc", "info", "DMARC", m.dmarc.record, m.dmarc.host, "", "", ""]);
    m.notes.forEach((n, i) => rows.push(["mail", `note_${i}`, "info", "Mail note", n, "", "", "", ""]));
  }
  if (r.siteMeta) {
    for (const key of ["robots", "securityTxt"] as const) {
      const b = r.siteMeta![key];
      if ("skipped" in b && b.skipped) {
        rows.push(["site_meta", key, "info", key, b.reason, "", "", "", ""]);
      } else {
        const f = b as FetchedMeta;
        rows.push([
          "site_meta",
          key,
          "info",
          `${key} HTTP ${f.status}`,
          f.excerpt.slice(0, 800),
          f.finalUrl,
          "",
          "",
          "",
        ]);
      }
    }
  }
  if (r.subdomains?.subdomains?.length) {
    rows.push([
      "subdomains",
      "summary",
      "info",
      "Subdomain discovery",
      `${r.subdomains.count} host(s) for ${r.subdomains.domain}`,
      "",
      "",
      "",
      "",
    ]);
    for (const s of r.subdomains.subdomains) {
      rows.push(["subdomains", s.subdomain, "info", s.subdomain, s.source, "", "", "", ""]);
    }
  }
  if (r.googleDork && !("error" in r.googleDork) && Array.isArray(r.googleDork.hits)) {
    for (const h of r.googleDork.hits as { title?: string; link?: string; snippet?: string; dorkTitle?: string }[]) {
      rows.push([
        "google_dork",
        h.dorkTitle || "hit",
        "info",
        h.title || "",
        h.snippet || "",
        h.link || "",
        "",
        "",
        "",
      ]);
    }
  }
  if (r.wpCron && typeof r.wpCron === "object" && !("error" in r.wpCron)) {
    const w = r.wpCron as {
      checks?: { path: string; status: number; exposed: boolean; matcher: string; recommendation: string }[];
      infraChecks?: { path: string; status: number; exposed: boolean; severity: string; matcher: string; recommendation: string }[];
    };
    (w.checks || []).forEach((c, i) =>
      rows.push([
        "wp_infra",
        `wp_${i}`,
        c.exposed ? "medium" : "info",
        c.path,
        `HTTP ${c.status} ${c.matcher}`,
        c.recommendation,
        "",
        "",
        "",
      ]),
    );
    (w.infraChecks || []).forEach((c, i) =>
      rows.push([
        "wp_infra",
        `infra_${i}`,
        c.exposed ? c.severity : "info",
        c.path,
        `HTTP ${c.status} ${c.matcher}`,
        c.recommendation,
        "",
        "",
        "",
      ]),
    );
  }
  if (r.takeover && typeof r.takeover === "object" && !("error" in r.takeover)) {
    const risky = (r.takeover as { risky?: { host: string; detail: string; cname?: string | null }[] }).risky || [];
    for (const t of risky) {
      rows.push([
        "takeover",
        t.host,
        "high",
        "Subdomain takeover signal",
        t.detail,
        t.cname ? `CNAME: ${t.cname}` : "",
        "Validate DNS and cloud DNS records.",
        "",
        "",
      ]);
    }
  }
  const vt = r.virustotal as { skipped?: boolean; error?: string; analysis?: { headline?: string; summaryPlain?: string } } | undefined;
  if (vt && !vt.skipped && !vt.error && vt.analysis) {
    rows.push([
      "virustotal",
      "summary",
      "info",
      vt.analysis.headline || "VirusTotal",
      vt.analysis.summaryPlain || "",
      "",
      "",
      "",
      "",
    ]);
  }
  if (r.ai) {
    if (r.ai.executiveSummary) {
      rows.push(["ai", "executive", "info", "AI executive summary", r.ai.executiveSummary, "", "", "", ""]);
    }
    if (r.ai.riskLevel) {
      rows.push(["ai", "risk_level", "info", "AI risk level", r.ai.riskLevel, "", "", "", ""]);
    }
    (r.ai.recommendations || []).forEach((rec, i) =>
      rows.push(["ai", `rec_${i}`, "info", "AI recommendation", rec, "", "", "", ""]),
    );
  }
  return rows.map((row) => row.map((c) => csvEscape(String(c))).join(",")).join("\n");
}

function buildScanSummaryText(r: ReportExporterResults): string {
  const scan = r.scan;
  const lines: string[] = [];
  if (scan) {
    const pass = scan.headers.filter((h) => h.status === "pass").length;
    lines.push(`Argus scan — ${scan.target.hostname}`);
    lines.push(`Score ${scan.score}/100 (grade ${scan.grade})`);
    lines.push(`Headers: ${pass}/${scan.headers.length} pass`);
  }
  if (r.ssl) {
    lines.push(`TLS grade ${r.ssl.grade} · ${r.ssl.protocol ?? "protocol n/a"}`);
  }
  if (r.ports?.highRiskOpenPortsCount != null) {
    lines.push(`High-risk open ports (heuristic): ${r.ports.highRiskOpenPortsCount}`);
  }
  if (Array.isArray(r.ports?.cves) && r.ports!.cves!.length) {
    lines.push(`CVE tags: ${r.ports!.cves!.slice(0, 15).join(", ")}${r.ports!.cves!.length > 15 ? "…" : ""}`);
  }
  if (r.mailAuth) {
    lines.push(
      `Mail: MX ${r.mailAuth.mx.length} · SPF ${r.mailAuth.spf ? "yes" : "no"} · DMARC ${r.mailAuth.dmarc ? "yes" : "no"}`,
    );
  }
  if (r.subdomains?.subdomains?.length) {
    lines.push(`Subdomains found: ${r.subdomains.count ?? r.subdomains.subdomains.length}`);
  }
  if (r.googleDork && Array.isArray(r.googleDork.hits)) {
    lines.push(`Google dork hits: ${(r.googleDork.hits as unknown[]).length}`);
  }
  if (r.ai?.riskLevel) {
    lines.push(`AI risk: ${r.ai.riskLevel}`);
  }
  if (Array.isArray(r.ai?.recommendations) && r.ai!.recommendations!.length) {
    lines.push("Next steps:");
    r.ai!.recommendations!.slice(0, 5).forEach((x, i) => lines.push(`  ${i + 1}. ${x}`));
  }
  lines.push(`Exported ${new Date().toISOString()}`);
  return lines.join("\n");
}

function triggerDownload(blob: Blob, filename: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

export default function ReportExporter({ results }: { results: ReportExporterResults }) {
  const { t } = useI18n();
  const scan = results.scan;
  const host = scan?.target.hostname ?? "report";
  const [pdfBusy, setPdfBusy] = useState(false);
  const [reportPreparedBy, setReportPreparedBy] = useState("");
  const [copied, setCopied] = useState(false);

  const downloadJson = useCallback(() => {
    const by = reportPreparedBy.trim();
    const payload = by ? { ...results, reportPreparedBy: by } : results;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    triggerDownload(blob, `argus-${host}-${new Date().toISOString().split("T")[0]}.json`);
  }, [results, host, reportPreparedBy]);

  const downloadCsv = useCallback(() => {
    const by = reportPreparedBy.trim();
    let csv = buildCsv(results);
    if (by) {
      csv = `report_prepared_by,${csvEscape(by)}\n${csv}`;
    }
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    triggerDownload(blob, `argus-${host}-${new Date().toISOString().split("T")[0]}.csv`);
  }, [results, host, reportPreparedBy]);

  const downloadPdf = useCallback(async () => {
    if (!scan) return;
    setPdfBusy(true);
    try {
      const by = reportPreparedBy.trim();
      const res = await fetch("/api/report/pdf", {
        method: "POST",
        headers: jsonHeadersWithArgus(),
        body: JSON.stringify(by ? { ...results, reportPreparedBy: by } : results),
      });
      const ct = res.headers.get("Content-Type") || "";
      if (!res.ok) {
        const err = ct.includes("application/json") ? await res.json().catch(() => ({})) : {};
        const text = !ct.includes("application/json") ? await res.text().catch(() => "") : "";
        throw new Error(
          (err as { error?: string }).error ||
            (text ? text.slice(0, 200) : null) ||
            `PDF failed (${res.status})`,
        );
      }
      if (!ct.includes("application/pdf")) {
        const text = await res.text().catch(() => "");
        throw new Error(text ? `Expected PDF, got: ${text.slice(0, 120)}` : "Server did not return a PDF (wrong Content-Type).");
      }
      const blob = await res.blob();
      triggerDownload(blob, `argus-${host}-${new Date().toISOString().split("T")[0]}.pdf`);
    } catch (e) {
      console.error(e);
      alert(e instanceof Error ? e.message : "PDF download failed");
    } finally {
      setPdfBusy(false);
    }
  }, [results, scan, host, reportPreparedBy]);

  const copySummary = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(buildScanSummaryText(results));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      alert("Could not copy to clipboard");
    }
  }, [results]);

  const downloadSarif = useCallback(() => {
    const sarif = buildSecuritySarif({
      scan: results.scan,
      ssl: results.ssl,
      ports: results.ports,
    });
    const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: "application/json" });
    triggerDownload(blob, `argus-${host}-${new Date().toISOString().split("T")[0]}.sarif.json`);
  }, [results.scan, results.ssl, results.ports, host]);

  if (!scan) return null;

  return (
    <div className="rounded-xl border border-accent/30 bg-accent/5 p-4 sm:p-5 space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-white">{t("scanner.exportReport")}</h3>
          <p className="text-[11px] text-text-dim mt-0.5">
            PDF and CSV include headers, cookies, TLS, ports, mail/DNS, robots/security.txt, subdomains, dorks, secrets,
            libraries, VirusTotal, takeover, wp-cron/infra, and AI when present. JSON is the full raw snapshot. SARIF is
            a subset for CI tools.
          </p>
        </div>
      </div>
      <div className="space-y-1.5">
        <label htmlFor="report-prepared-by" className="text-[11px] text-text-dim block">
          Your name on the report <span className="text-text-muted">(optional)</span>
        </label>
        <input
          id="report-prepared-by"
          type="text"
          maxLength={120}
          value={reportPreparedBy}
          onChange={(e) => setReportPreparedBy(e.target.value)}
          placeholder="e.g. analyst name — appears on PDF / export metadata if set"
          className="w-full max-w-md rounded-lg border border-border bg-bg px-3 py-2 text-sm text-white placeholder:text-text-dim focus:outline-none focus:ring-2 focus:ring-accent/40"
        />
      </div>
      <div className="flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center gap-2 sm:gap-3">
        <button
          type="button"
          disabled={pdfBusy}
          onClick={downloadPdf}
          className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-accent hover:bg-accent-hover disabled:opacity-60 disabled:pointer-events-none text-white text-sm font-semibold rounded-lg transition-colors"
        >
          {pdfBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileDown className="w-4 h-4" />}
          {pdfBusy ? "Building PDF…" : "Download PDF"}
        </button>
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
          onClick={downloadSarif}
          className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-surface-2 hover:bg-border border border-border text-white text-sm font-semibold rounded-lg transition-colors"
        >
          <Braces className="w-4 h-4" />
          SARIF (JSON)
        </button>
        <button
          type="button"
          onClick={() => void copySummary()}
          className="inline-flex items-center justify-center gap-2 px-5 py-2.5 bg-surface-2 hover:bg-border border border-border text-white text-sm font-semibold rounded-lg transition-colors"
        >
          {copied ? <Check className="w-4 h-4 text-success" /> : <Copy className="w-4 h-4" />}
          {copied ? "Copied" : "Copy summary"}
        </button>
      </div>
      <p className="text-[10px] text-text-dim">
        PDF mirrors the dashboard modules listed above (same data as JSON export, formatted for reading).
      </p>
    </div>
  );
}
