import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from "pdf-lib";
import type { ScanResult, SSLResult, AIReport } from "@/lib/types";
import type { PdfNarrative } from "@/lib/pdf-narrative";
import type { LibraryInventoryResult } from "@/lib/library-inventory";
import type { FetchedMeta, MailAuthResult, SiteMetaResult } from "@/lib/mail-site-types";
import { sanitizePdfText } from "@/lib/pdf-text";

const A4_W = 595.28;
const A4_H = 841.89;
const MARGIN = 48;
const CONTENT_W = A4_W - 2 * MARGIN;

const C = {
  accent: rgb(0.39, 0.4, 0.94),
  accentDark: rgb(0.25, 0.27, 0.7),
  success: rgb(0.13, 0.77, 0.37),
  danger: rgb(0.94, 0.27, 0.27),
  warning: rgb(0.96, 0.62, 0.04),
  info: rgb(0.23, 0.51, 0.96),
  muted: rgb(0.39, 0.45, 0.55),
  surface: rgb(0.93, 0.94, 0.97),
  surface2: rgb(0.86, 0.88, 0.94),
  ink: rgb(0.12, 0.14, 0.2),
  white: rgb(1, 1, 1),
};

function impactText(severity: string): string {
  switch (severity) {
    case "critical":
      return "Critical: could mean direct compromise, stolen data, or attackers abusing your systems.";
    case "high":
      return "High: serious weakness — often leads to stolen sessions, cross-site attacks, or leaked data if combined with other issues.";
    case "medium":
      return "Medium: not an emergency alone, but weakens your overall defenses.";
    case "low":
      return "Low: small hardening gap or minor information leak.";
    default:
      return "Informational.";
  }
}

function stepsForHeader(hostname: string, name: string): string {
  return `1) Open DevTools -> Network.\n2) Load https://${hostname}/\n3) Check response headers for "${name}".\n4) Compare with a secure headers checklist (OWASP).`;
}

function pocHeader(hostname: string, name: string): string {
  return `curl -sI "https://${hostname}/" | grep -i "${name.split("-")[0]}"`;
}

function wrapParagraph(text: string, font: PDFFont, size: number, maxWidth: number): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    if (!word) continue;
    const testLine = line ? `${line} ${word}` : word;
    if (font.widthOfTextAtSize(testLine, size) <= maxWidth) {
      line = testLine;
    } else {
      if (line) lines.push(line);
      if (font.widthOfTextAtSize(word, size) > maxWidth) {
        let rest = word;
        while (rest.length > 0) {
          let lo = 0;
          let hi = rest.length;
          while (lo < hi) {
            const mid = Math.ceil((lo + hi) / 2);
            if (font.widthOfTextAtSize(rest.slice(0, mid), size) <= maxWidth) lo = mid;
            else hi = mid - 1;
          }
          const take = Math.max(1, lo);
          lines.push(rest.slice(0, take));
          rest = rest.slice(take);
        }
        line = "";
      } else {
        line = word;
      }
    }
  }
  if (line) lines.push(line);
  return lines.length ? lines : [""];
}

type DrawCtx = {
  pdfDoc: PDFDocument;
  page: PDFPage;
  y: number;
  helv: PDFFont;
  helvBold: PDFFont;
};

function newPage(ctx: DrawCtx): void {
  ctx.page = ctx.pdfDoc.addPage([A4_W, A4_H]);
  ctx.y = A4_H - MARGIN;
}

/** Only start a new page if fewer than `need` points remain above bottom margin. */
function ensureSpace(ctx: DrawCtx, need: number): void {
  if (ctx.y < MARGIN + need) {
    newPage(ctx);
  }
}

function gradeRgb(grade: string) {
  if (grade.startsWith("A")) return C.success;
  if (grade === "B") return C.info;
  if (grade === "C") return C.warning;
  if (grade === "D") return rgb(0.98, 0.45, 0.2);
  return C.danger;
}

function drawCoverBand(ctx: DrawCtx): void {
  ctx.page.drawRectangle({
    x: 0,
    y: A4_H - 120,
    width: A4_W,
    height: 120,
    color: C.accentDark,
  });
}

function drawTitleOnCover(ctx: DrawCtx, title: string, subtitle: string): void {
  ctx.page.drawText(sanitizePdfText(title), {
    x: MARGIN,
    y: A4_H - 72,
    size: 22,
    font: ctx.helvBold,
    color: C.white,
  });
  ctx.page.drawText(sanitizePdfText(subtitle), {
    x: MARGIN,
    y: A4_H - 98,
    size: 11,
    font: ctx.helv,
    color: rgb(0.85, 0.86, 1),
  });
}

function drawScorePanel(ctx: DrawCtx, score: number, grade: string): void {
  ensureSpace(ctx, 100);
  const panelBottom = ctx.y - 88;
  const panelH = 88;
  ctx.page.drawRectangle({
    x: MARGIN,
    y: panelBottom,
    width: CONTENT_W,
    height: panelH,
    color: C.surface,
    borderColor: C.accent,
    borderWidth: 1,
  });

  const gcol = gradeRgb(grade);
  ctx.page.drawText(sanitizePdfText(grade), {
    x: MARGIN + 16,
    y: panelBottom + 52,
    size: 36,
    font: ctx.helvBold,
    color: gcol,
  });
  ctx.page.drawText(sanitizePdfText("Security grade"), {
    x: MARGIN + 16,
    y: panelBottom + 38,
    size: 9,
    font: ctx.helv,
    color: C.muted,
  });

  const barX = MARGIN + 100;
  const barW = CONTENT_W - 116;
  const barH = 16;
  const barY = panelBottom + 48;
  ctx.page.drawRectangle({ x: barX, y: barY, width: barW, height: barH, color: C.surface2 });
  const fillW = (barW * Math.min(100, Math.max(0, score))) / 100;
  ctx.page.drawRectangle({ x: barX, y: barY, width: fillW, height: barH, color: gcol });
  ctx.page.drawText(sanitizePdfText(`${score} / 100`), {
    x: barX + barW / 2 - 18,
    y: barY + 4,
    size: 9,
    font: ctx.helvBold,
    color: C.ink,
  });

  ctx.page.drawText(sanitizePdfText("Score bar: higher is better. Grade blends headers, cookies, and fingerprint hints."), {
    x: MARGIN + 16,
    y: panelBottom + 22,
    size: 8,
    font: ctx.helv,
    color: C.muted,
  });

  ctx.y = panelBottom - 12;
}

function drawHeaderSummaryChart(ctx: DrawCtx, scan: ScanResult): void {
  const pass = scan.headers.filter((h) => h.status === "pass").length;
  const fail = scan.headers.filter((h) => h.status === "fail").length;
  const warn = scan.headers.filter((h) => h.status === "warn").length;
  const total = Math.max(1, pass + fail + warn);
  ensureSpace(ctx, 52);
  const h = 28;
  const bottom = ctx.y - h - 14;
  ctx.page.drawText(sanitizePdfText("Headers at a glance"), {
    x: MARGIN,
    y: bottom + h + 8,
    size: 10,
    font: ctx.helvBold,
    color: C.accentDark,
  });
  let x = MARGIN;
  const seg = (n: number, color: ReturnType<typeof rgb>, label: string) => {
    if (n <= 0) return;
    const w = (CONTENT_W * n) / total;
    ctx.page.drawRectangle({ x, y: bottom, width: Math.max(w, 2), height: h, color });
    ctx.page.drawText(sanitizePdfText(`${label} ${n}`), {
      x: x + 4,
      y: bottom + 8,
      size: 8,
      font: ctx.helvBold,
      color: C.white,
    });
    x += w;
  };
  seg(pass, C.success, "OK");
  seg(warn, C.warning, "Warn");
  seg(fail, C.danger, "Fail");
  ctx.y = bottom - 10;
}

function drawSectionHeader(ctx: DrawCtx, title: string): void {
  ensureSpace(ctx, 34);
  const barH = 24;
  const bottom = ctx.y - 4;
  ctx.page.drawRectangle({
    x: MARGIN,
    y: bottom - barH + 4,
    width: CONTENT_W,
    height: barH,
    color: C.accent,
  });
  ctx.page.drawText(sanitizePdfText(title), {
    x: MARGIN + 10,
    y: bottom - barH + 9,
    size: 14,
    font: ctx.helvBold,
    color: C.white,
  });
  ctx.y = bottom - barH - 6;
}

function drawCallout(ctx: DrawCtx, text: string, size = 12): void {
  if (!text.trim()) return;
  const font = ctx.helv;
  const lines = text.split(/\n/).flatMap((para) => wrapParagraph(sanitizePdfText(para), font, size, CONTENT_W - 16));
  const blockH = lines.length * (size + 3) + 16;
  ensureSpace(ctx, blockH + 4);
  const bottom = ctx.y - blockH;
  ctx.page.drawRectangle({
    x: MARGIN,
    y: bottom,
    width: CONTENT_W,
    height: blockH,
    color: C.surface,
    borderColor: C.info,
    borderWidth: 0.5,
  });
  let ly = bottom + blockH - 12;
  for (const wl of lines) {
    ctx.page.drawText(wl, { x: MARGIN + 8, y: ly, size, font, color: C.ink });
    ly -= size + 3;
  }
  ctx.y = bottom - 8;
}

function drawLines(ctx: DrawCtx, text: string, size: number, bold: boolean, color = C.ink): void {
  const font = bold ? ctx.helvBold : ctx.helv;
  const paras = text.split(/\n/);
  for (const para of paras) {
    const wrapped = wrapParagraph(sanitizePdfText(para), font, size, CONTENT_W);
    for (const wl of wrapped) {
      ensureSpace(ctx, size + 6);
      ctx.page.drawText(wl, { x: MARGIN, y: ctx.y, size, font, color });
      ctx.y -= size + 3;
    }
  }
}

function drawLibrarySummary(ctx: DrawCtx, inv: LibraryInventoryResult): void {
  ensureSpace(ctx, 70);
  const bottom = ctx.y - 56;
  const rowH = 18;
  ctx.page.drawText(sanitizePdfText("Library inventory summary"), {
    x: MARGIN,
    y: bottom + 58,
    size: 10,
    font: ctx.helvBold,
    color: C.accentDark,
  });
  const cols = [
    { label: "Passed", n: inv.passed, col: C.success },
    { label: "Warnings", n: inv.warned, col: C.warning },
    { label: "Failed (CVE)", n: inv.failed, col: C.danger },
  ];
  let cx = MARGIN;
  const cw = CONTENT_W / 3 - 6;
  for (const c of cols) {
    ctx.page.drawRectangle({ x: cx, y: bottom + 12, width: cw, height: rowH + 8, color: C.surface2 });
    ctx.page.drawText(sanitizePdfText(String(c.n)), {
      x: cx + 8,
      y: bottom + 26,
      size: 16,
      font: ctx.helvBold,
      color: c.col,
    });
    ctx.page.drawText(sanitizePdfText(c.label), {
      x: cx + 8,
      y: bottom + 14,
      size: 8,
      font: ctx.helv,
      color: C.muted,
    });
    cx += cw + 8;
  }
  ctx.y = bottom - 4;
  drawCallout(ctx, inv.explanation, 11);
}

export async function buildSecurityPdfBuffer(params: {
  scan: ScanResult;
  ssl?: SSLResult;
  ai?: AIReport;
  ports?: {
    ip: string;
    ports: { port: number; service: string; exposureRisk?: string }[];
    cves?: string[];
    highRiskOpenPortsCount?: number;
  };
  sourceAudit?: Record<string, unknown>;
  takeover?: Record<string, unknown>;
  wpCron?: Record<string, unknown>;
  virustotal?: Record<string, unknown>;
  narrative?: PdfNarrative | null;
  libraryInventory?: LibraryInventoryResult | null;
  mailAuth?: MailAuthResult | null;
  siteMeta?: SiteMetaResult | null;
  subdomains?: {
    domain: string;
    count: number;
    subdomains: { subdomain: string; source: string }[];
  } | null;
  googleDork?: Record<string, unknown> | null;
  /** Optional display name of the person who ran / owns the export */
  reportPreparedBy?: string | null;
}): Promise<Uint8Array> {
  const {
    scan,
    ssl,
    ai,
    ports,
    sourceAudit,
    takeover,
    wpCron,
    virustotal,
    narrative,
    libraryInventory,
    mailAuth,
    siteMeta,
    subdomains,
    googleDork,
    reportPreparedBy,
  } = params;

  const pdfDoc = await PDFDocument.create();
  const helv = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const helvBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  const ctx: DrawCtx = {
    pdfDoc,
    page: pdfDoc.addPage([A4_W, A4_H]),
    y: A4_H - MARGIN,
    helv,
    helvBold,
  };

  drawCoverBand(ctx);
  drawTitleOnCover(ctx, "Argus", narrative?.tagline || "Security Intelligence");
  ctx.y = A4_H - 140;

  const metaBits = [
    `Target: ${scan.target.hostname} (${scan.target.url})`,
    `Generated: ${new Date().toISOString()}`,
  ];
  const by = typeof reportPreparedBy === "string" ? reportPreparedBy.trim() : "";
  if (by) metaBits.push(`Report prepared by: ${by}`);
  drawLines(ctx, metaBits.join("\n"), 12, false, C.muted);
  ctx.y -= 8;

  drawScorePanel(ctx, scan.score, scan.grade);
  drawHeaderSummaryChart(ctx, scan);

  drawSectionHeader(ctx, "HTTP response");
  drawLines(
    ctx,
    `Status code: ${scan.statusCode} · Response time: ${scan.responseTime} ms · Final URL: ${scan.target.url}`,
    10,
    false,
  );
  if (scan.redirectChain?.length) {
    drawLines(ctx, `Redirect chain: ${scan.redirectChain.join(" → ")}`, 9, false, C.muted);
  }
  ctx.y -= 4;

  drawSectionHeader(ctx, "Cookies");
  if (!scan.cookies.length) {
    drawLines(ctx, "No Set-Cookie headers were returned on this response.", 10, false, C.muted);
  } else {
    for (const c of scan.cookies) {
      drawLines(
        ctx,
        `${c.name}: HttpOnly=${c.httpOnly} · Secure=${c.secure} · SameSite=${c.sameSite} · path=${c.path}`,
        9,
        true,
      );
      if (c.issues.length === 0) drawLines(ctx, "No cookie policy issues flagged.", 8, false, C.success);
      else for (const iss of c.issues) drawLines(ctx, `  • ${iss}`, 9, false, C.warning);
    }
  }
  ctx.y -= 4;

  drawSectionHeader(ctx, "Fingerprinted technologies");
  if (!scan.technologies?.length) {
    drawLines(ctx, "No strong technology fingerprints from this response.", 10, false, C.muted);
  } else {
    const techLine = scan.technologies
      .map((t) => `${t.name}${t.version ? ` ${t.version}` : ""} (${t.category})`)
      .join(" · ");
    drawLines(ctx, techLine.slice(0, 3500), 9, false);
  }
  ctx.y -= 4;

  drawSectionHeader(ctx, "Complete security header audit");
  if (narrative?.headersIntro) drawCallout(ctx, narrative.headersIntro, 11);
  for (const h of scan.headers) {
    const statusCol =
      h.status === "pass" ? C.success : h.status === "warn" ? C.warning : C.danger;
    const val = (h.value || "").replace(/\s+/g, " ").trim();
    const line = `[${h.status.toUpperCase()}] ${h.name} (${h.severity}) — ${val ? val.slice(0, 140) + (val.length > 140 ? "…" : "") : "(empty)"}`;
    drawLines(ctx, line, 9, true, statusCol);
  }
  ctx.y -= 4;

  if (narrative?.readingGuide) {
    drawCallout(ctx, narrative.readingGuide, 12);
  }

  if (narrative?.executivePlain) {
    drawCallout(ctx, `Executive summary (plain English)\n${narrative.executivePlain}`, 12);
  } else if (ai?.executiveSummary) {
    drawCallout(ctx, `Executive summary\n${ai.executiveSummary}`, 12);
  }

  drawSectionHeader(ctx, "Header hardening — step-by-step (failed / warned only)");
  const badHeaders = scan.headers.filter((h) => h.status !== "pass");
  if (badHeaders.length === 0) {
    drawLines(ctx, "No failing or warning headers — see complete audit above.", 12, false, C.success);
  } else {
    for (const h of badHeaders) {
      drawLines(ctx, `${h.name} - ${h.status.toUpperCase()} (${h.severity})`, 12, true, C.danger);
      drawLines(
        ctx,
        `What it means: ${h.description}\nWhy it matters: ${impactText(h.severity)}\nWhat to do: ${h.remediation}\nHow to check: ${stepsForHeader(scan.target.hostname, h.name)}\nQuick test: ${pocHeader(scan.target.hostname, h.name)}`,
        9,
        false,
      );
      ctx.y -= 4;
    }
  }
  ctx.y -= 4;

  if (ssl) {
    drawSectionHeader(ctx, "TLS / HTTPS (certificate & protocol)");
    if (narrative?.sslIntro) drawCallout(ctx, narrative.sslIntro, 11);
    if (ssl.probeContext?.likelyCorporateTlsInspection && ssl.probeContext.notes?.length) {
      drawCallout(
        ctx,
        `TLS inspection note: ${ssl.probeContext.notes.join(" ")}`,
        10,
      );
    }
    drawLines(
      ctx,
      `Grade ${ssl.grade}, protocol ${ssl.protocol}, certificate expires in ${ssl.daysUntilExpiry} days.`,
      10,
      false,
    );
    const vuln = ssl.vulnerabilities.filter((x) => x.vulnerable);
    if (vuln.length === 0) {
      drawLines(ctx, "No extra TLS weaknesses were flagged by our automated checks.", 12, false, C.success);
    } else {
      for (const v of vuln) {
        drawLines(ctx, `${v.name}: ${v.description}`, 12, true, C.warning);
        drawLines(
          ctx,
          `${impactText("high")}\nFix: upgrade TLS settings and renew certificates on time. Test with SSL Labs or testssl.sh.`,
          9,
          false,
        );
      }
    }
    ctx.y -= 4;
  }

  if (ports?.ports?.length) {
    drawSectionHeader(ctx, "Internet-exposed ports (Shodan snapshot)");
    if (narrative?.portsIntro) drawCallout(ctx, narrative.portsIntro, 11);
    drawLines(
      ctx,
      `IP ${ports.ip}. High-risk port count: ${ports.highRiskOpenPortsCount ?? 0}. These are public observations — confirm what should be reachable.`,
      10,
      false,
    );
    for (const p of ports.ports.slice(0, 45)) {
      drawLines(
        ctx,
        `Port ${p.port} (${p.service})${p.exposureRisk ? ` - ${p.exposureRisk}` : ""}`,
        9,
        false,
      );
    }
    if (ports.cves?.length)
      drawLines(ctx, `Related CVE references (sample): ${ports.cves.slice(0, 25).join(", ")}`, 11, false, C.muted);
    ctx.y -= 4;
  }

  if (subdomains?.subdomains?.length) {
    drawSectionHeader(ctx, `Subdomains (${subdomains.count ?? subdomains.subdomains.length})`);
    drawLines(
      ctx,
      `Base domain: ${subdomains.domain}. Listing is a snapshot from certificate transparency / discovery — verify in your DNS console.`,
      9,
      false,
      C.muted,
    );
    const slice = subdomains.subdomains.slice(0, 150);
    for (const s of slice) {
      drawLines(ctx, `${s.subdomain}  [${s.source}]`, 8, false);
    }
    if (subdomains.subdomains.length > slice.length) {
      drawLines(
        ctx,
        `… and ${subdomains.subdomains.length - slice.length} more (use JSON export for the full list).`,
        9,
        false,
        C.muted,
      );
    }
    ctx.y -= 4;
  }

  if (mailAuth) {
    drawSectionHeader(ctx, "Mail authentication (MX / SPF / DMARC)");
    drawLines(
      ctx,
      `Primary host: ${mailAuth.hostname} · Lookups: ${mailAuth.checkedHosts.join(", ")}`,
      10,
      false,
    );
    if (mailAuth.mx.length === 0) {
      drawLines(ctx, "No MX records returned.", 9, false, C.warning);
    } else {
      for (const m of mailAuth.mx) {
        drawLines(ctx, `MX ${m.priority} ${m.exchange}`, 9, false);
      }
    }
    if (mailAuth.spf) {
      drawLines(ctx, `SPF @ ${mailAuth.spf.host}`, 9, true);
      drawLines(ctx, mailAuth.spf.record.slice(0, 2000), 8, false);
    } else drawLines(ctx, "No SPF TXT record found for the checked host(s).", 9, false, C.warning);
    if (mailAuth.dmarc) {
      drawLines(ctx, `DMARC @ ${mailAuth.dmarc.host}`, 9, true);
      drawLines(ctx, mailAuth.dmarc.record.slice(0, 2000), 8, false);
    } else drawLines(ctx, "No DMARC record found at _dmarc (may be missing policy).", 9, false, C.warning);
    for (const n of mailAuth.notes.slice(0, 12)) {
      drawLines(ctx, `Note: ${n}`, 8, false, C.muted);
    }
    ctx.y -= 4;
  }

  if (siteMeta) {
    drawSectionHeader(ctx, "robots.txt & security.txt");
    for (const key of ["robots", "securityTxt"] as const) {
      const block = siteMeta[key];
      if ("skipped" in block && block.skipped) {
        drawLines(ctx, `${key}: not fetched — ${block.reason}`, 9, false, C.warning);
        continue;
      }
      const b = block as FetchedMeta;
      drawLines(ctx, `${key}: HTTP ${b.status} — ${b.finalUrl}`, 9, true);
      if (b.contentType) drawLines(ctx, `Content-Type: ${b.contentType}`, 8, false, C.muted);
      if (b.accessControlAllowOrigin)
        drawLines(ctx, `Access-Control-Allow-Origin: ${b.accessControlAllowOrigin}`, 8, false, C.muted);
      const ex = (b.excerpt || "").replace(/\s+/g, " ").trim();
      if (ex) drawLines(ctx, ex.slice(0, 1800) + (ex.length > 1800 ? "…" : ""), 8, false);
      ctx.y -= 2;
    }
    ctx.y -= 4;
  }

  const secrets =
    sourceAudit && Array.isArray(sourceAudit.secretFindings) ? (sourceAudit.secretFindings as unknown[]) : [];
  if (secrets.length > 0) {
    drawSectionHeader(ctx, "Secrets & sensitive patterns (redacted)");
    if (narrative?.secretsIntro) drawCallout(ctx, narrative.secretsIntro, 11);
    for (const f of secrets.slice(0, 30) as {
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
      drawLines(ctx, `${f.label} [${f.severity}] ${f.redacted}`, 12, true, C.danger);
      const locLine =
        typeof f.lineNumber === "number"
          ? `Approx. line ${f.lineNumber}${typeof f.columnApprox === "number" ? `, column ~${f.columnApprox}` : ""}`
          : "";
      const detailParts = [
        `URL: ${f.sourceUrl}`,
        locLine,
        f.contextSnippet ? `Context (secret redacted in scan): ${f.contextSnippet}` : "",
        f.locateHint ? `How to locate: ${f.locateHint}` : "",
        "Plain summary: Key-like value may be exposed to the browser or a public file. Treat as real until proven otherwise.",
        `Fix: ${f.hint}`,
      ].filter((s) => s.length > 0);
      drawLines(ctx, detailParts.join("\n"), 12, false);
      ctx.y -= 2;
    }
    ctx.y -= 4;
  }

  if (libraryInventory && libraryInventory.items.length > 0) {
    drawSectionHeader(ctx, "JavaScript libraries & frameworks");
    if (narrative?.librariesIntro) drawCallout(ctx, narrative.librariesIntro, 11);
    drawLibrarySummary(ctx, libraryInventory);
    const preview = libraryInventory.items.slice(0, 28);
    for (const it of preview) {
      const col = it.status === "fail" ? C.danger : it.status === "warn" ? C.warning : C.success;
      drawLines(
        ctx,
        `${it.name}${it.version ? ` v${it.version}` : ""} [${it.status.toUpperCase()}] (${it.source})`,
        9,
        true,
        col,
      );
      drawLines(ctx, it.detail, 11, false);
      if (it.referenceUrl) drawLines(ctx, `Ref: ${it.referenceUrl}`, 12, false, C.muted);
      ctx.y -= 2;
    }
    if (libraryInventory.items.length > preview.length) {
      drawLines(ctx, `... and ${libraryInventory.items.length - preview.length} more (see JSON export).`, 11, false, C.muted);
    }
    ctx.y -= 4;
  } else if (Array.isArray(sourceAudit?.retireMatches) && (sourceAudit!.retireMatches as unknown[]).length > 0) {
    drawSectionHeader(ctx, "Outdated libraries (CVE matches)");
    for (const r of sourceAudit!.retireMatches as {
      library: string;
      version: string;
      cves: string[];
      summary: string;
      scriptUrl: string;
      detectionSource?: string;
    }[]) {
      const src = r.detectionSource === "content" ? " (detected inside JS file)" : "";
      drawLines(ctx, `${r.library} ${r.version}${src} - ${(r.cves || []).join(", ")}`, 12, true, C.danger);
      drawLines(ctx, `${r.summary}\nScript: ${r.scriptUrl}`, 12, false);
    }
    ctx.y -= 4;
  }

  const vt = virustotal as {
    skipped?: boolean;
    error?: string;
    analysis?: { headline: string; summaryPlain: string; concerns?: { title: string; detail: string; severity: string }[] };
  } | undefined;
  if (vt && !vt.skipped && !vt.error && vt.analysis) {
    drawSectionHeader(ctx, "VirusTotal domain reputation");
    if (narrative?.vtIntro) drawCallout(ctx, narrative.vtIntro, 11);
    drawCallout(ctx, `${vt.analysis.headline}\n${vt.analysis.summaryPlain}`, 12);
    for (const c of vt.analysis.concerns || []) {
      const col = c.severity === "high" ? C.danger : c.severity === "medium" ? C.warning : C.muted;
      drawLines(ctx, `${c.title} (${c.severity})`, 12, true, col);
      drawLines(ctx, c.detail, 11, false);
    }
    ctx.y -= 4;
  }

  if (takeover && typeof takeover.riskyCount === "number") {
    drawSectionHeader(ctx, "Subdomain takeover heuristics");
    if (narrative?.takeoverIntro) drawCallout(ctx, narrative.takeoverIntro, 11);
    const risky = (takeover.risky as { host: string; detail: string; cname?: string | null }[]) || [];
    if (risky.length === 0) {
      drawLines(
        ctx,
        "No high-confidence dangling takeover signals were found for the hosts we tested. Run the extended subdomain check in the app if you discovered many subdomains.",
        9,
        false,
        C.success,
      );
    } else {
      drawLines(ctx, `Flagged hosts: ${risky.length}. Please confirm with DNS and your cloud console.`, 12, true, C.warning);
      for (const r of risky.slice(0, 20)) {
        drawLines(ctx, `${r.host}: ${r.detail}`, 12, false);
        if (r.cname) drawLines(ctx, `CNAME -> ${r.cname}`, 11, false, C.muted);
      }
    }
    ctx.y -= 4;
  }

  if (wpCron && typeof wpCron === "object" && !("error" in wpCron)) {
    drawSectionHeader(ctx, "WordPress wp-cron & infrastructure exposure");
    const w = wpCron as {
      isWordPressCronInteresting?: boolean;
      checks?: { path: string; status: number; exposed: boolean; matcher: string; recommendation: string; category?: string }[];
      infraChecks?: { path: string; status: number; exposed: boolean; matcher: string; severity: string; recommendation: string; category?: string }[];
    };
    if (w.isWordPressCronInteresting) {
      drawLines(
        ctx,
        "wp-cron.php matched public exposure heuristics. Prefer authenticating cron via system cron, not the public web.",
        9,
        false,
        C.warning,
      );
    }
    if (Array.isArray(w.checks) && w.checks.length) {
      drawLines(ctx, "WP / cron probes:", 10, true);
      for (const c of w.checks) {
        const flag = c.exposed ? "EXPOSED" : "ok";
        drawLines(
          ctx,
          `${flag} ${c.path} → HTTP ${c.status} (${c.matcher})\n${c.recommendation}`,
          8,
          false,
          c.exposed ? C.warning : C.muted,
        );
      }
    }
    if (Array.isArray(w.infraChecks) && w.infraChecks.length) {
      drawLines(ctx, "Infra / docs / metrics probes:", 10, true);
      for (const c of w.infraChecks) {
        const sev = c.severity === "critical" || c.severity === "high" ? C.danger : C.muted;
        drawLines(
          ctx,
          `${c.exposed ? "EXPOSED" : "not exposed"} [${c.severity}] ${c.path} HTTP ${c.status}\n${c.matcher}\n${c.recommendation}`,
          8,
          false,
          c.exposed ? sev : C.muted,
        );
      }
    }
    if (!w.isWordPressCronInteresting && !w.checks?.length && !w.infraChecks?.length) {
      drawLines(ctx, "No wp-cron / infra probe rows in this payload.", 9, false, C.muted);
    }
    ctx.y -= 4;
  }

  const gd = googleDork;
  if (gd && typeof gd === "object" && !("error" in gd) && Array.isArray(gd.hits) && (gd.hits as unknown[]).length > 0) {
    drawSectionHeader(ctx, "Search-engine visibility (Google dork sample)");
    if (typeof gd.note === "string" && gd.note) drawLines(ctx, gd.note, 9, false, C.muted);
    for (const h of (gd.hits as { title?: string; link?: string; snippet?: string; dorkTitle?: string }[]).slice(0, 28)) {
      drawLines(ctx, `${h.dorkTitle || "Query"}: ${h.title || "(no title)"}`, 9, true);
      if (h.link) drawLines(ctx, h.link, 8, false, C.info);
      if (h.snippet) drawLines(ctx, h.snippet.replace(/\s+/g, " ").slice(0, 400), 8, false);
      ctx.y -= 2;
    }
    ctx.y -= 4;
  }

  if (ai?.recommendations?.length) {
    drawSectionHeader(ctx, "Prioritized next steps (AI)");
    ai.recommendations.forEach((r, i) => {
      drawLines(ctx, `${i + 1}. ${r}`, 12, false);
    });
    ctx.y -= 4;
  }

  if (narrative?.closing) {
    drawCallout(ctx, narrative.closing, 12);
  }

  drawLines(ctx, "--- End of Argus report ---", 11, false, C.muted);

  return pdfDoc.save();
}
