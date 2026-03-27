import { PDFDocument, StandardFonts, rgb, LineCapStyle, type PDFFont, type PDFPage } from "pdf-lib";
import type { CodeFinding, CodeReviewResult } from "@/lib/types";
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

function ensureSpace(ctx: DrawCtx, need: number): void {
  if (ctx.y < MARGIN + need) newPage(ctx);
}

function riskRgb(risk: string) {
  if (risk === "critical") return C.danger;
  if (risk === "high") return rgb(0.98, 0.45, 0.2);
  if (risk === "medium") return C.warning;
  if (risk === "low") return C.info;
  return C.success;
}

function gradeLetter(score: number): string {
  if (score >= 93) return "A";
  if (score >= 85) return "B";
  if (score >= 75) return "C";
  if (score >= 65) return "D";
  return "F";
}

function scoreMeterRgb(score: number) {
  if (score < 35) return C.danger;
  if (score < 60) return C.warning;
  return C.success;
}

/** Segmented circular meter (PDF coords, y up). */
function drawScoreRing(page: PDFPage, cx: number, cy: number, r: number, score: number): void {
  const n = 72;
  const frac = Math.min(1, Math.max(0, score / 100));
  const meter = scoreMeterRgb(score);
  const track = rgb(0.82, 0.84, 0.9);
  for (let i = 0; i < n; i++) {
    const a0 = (-Math.PI / 2) + (i / n) * 2 * Math.PI;
    const a1 = (-Math.PI / 2) + ((i + 1) / n) * 2 * Math.PI;
    const col = i / n < frac ? meter : track;
    page.drawLine({
      start: { x: cx + r * Math.cos(a0), y: cy + r * Math.sin(a0) },
      end: { x: cx + r * Math.cos(a1), y: cy + r * Math.sin(a1) },
      thickness: 8.5,
      color: col,
      lineCap: LineCapStyle.Round,
    });
  }
}

function sevRgb(sev: string) {
  if (sev === "critical") return C.danger;
  if (sev === "high") return rgb(0.98, 0.45, 0.2);
  if (sev === "medium") return C.warning;
  if (sev === "low") return C.info;
  return C.muted;
}

function drawLines(ctx: DrawCtx, text: string, size: number, bold: boolean, color = C.ink): void {
  const font = bold ? ctx.helvBold : ctx.helv;
  const paras = text.split(/\n/);
  for (const para of paras) {
    const wrapped = wrapParagraph(sanitizePdfText(para), font, size, CONTENT_W - 8);
    for (const wl of wrapped) {
      ensureSpace(ctx, size + 6);
      ctx.page.drawText(wl, { x: MARGIN, y: ctx.y, size, font, color });
      ctx.y -= size + 3;
    }
  }
}

function drawCover(ctx: DrawCtx, result: CodeReviewResult): void {
  ctx.page.drawRectangle({
    x: 0,
    y: A4_H - 110,
    width: A4_W,
    height: 110,
    color: C.accentDark,
  });
  ctx.page.drawText(sanitizePdfText("Argus"), {
    x: MARGIN,
    y: A4_H - 58,
    size: 26,
    font: ctx.helvBold,
    color: C.white,
  });
  ctx.page.drawText(sanitizePdfText("Security Intelligence"), {
    x: MARGIN,
    y: A4_H - 82,
    size: 12,
    font: ctx.helvBold,
    color: rgb(0.92, 0.93, 1),
  });
  ctx.page.drawText(sanitizePdfText("Code review · static + optional AI"), {
    x: MARGIN,
    y: A4_H - 98,
    size: 10,
    font: ctx.helv,
    color: rgb(0.78, 0.8, 0.95),
  });
  ctx.y = A4_H - 130;

  const rcol = riskRgb(result.overallRisk);
  const letter = gradeLetter(result.score);
  const letterCol = scoreMeterRgb(result.score);
  ensureSpace(ctx, 118);
  const panelH = 102;
  const panelBottom = ctx.y - panelH;
  ctx.page.drawRectangle({
    x: MARGIN,
    y: panelBottom,
    width: CONTENT_W,
    height: panelH,
    color: C.surface,
    borderColor: C.accent,
    borderWidth: 1,
  });

  const ringCx = MARGIN + 48;
  const ringCy = panelBottom + panelH / 2;
  const ringR = 34;
  drawScoreRing(ctx.page, ringCx, ringCy, ringR, result.score);

  const lw = ctx.helvBold.widthOfTextAtSize(letter, 26);
  ctx.page.drawText(sanitizePdfText(letter), {
    x: ringCx - lw / 2,
    y: ringCy + 6,
    size: 26,
    font: ctx.helvBold,
    color: letterCol,
  });
  const sub = `${result.score} / 100`;
  const sw = ctx.helv.widthOfTextAtSize(sub, 10);
  ctx.page.drawText(sanitizePdfText(sub), {
    x: ringCx - sw / 2,
    y: ringCy - 8,
    size: 10,
    font: ctx.helv,
    color: C.muted,
  });

  const colLeft = MARGIN + 100;
  ctx.page.drawText(sanitizePdfText("Security score"), {
    x: colLeft,
    y: panelBottom + 72,
    size: 14,
    font: ctx.helvBold,
    color: C.ink,
  });
  ctx.page.drawText(sanitizePdfText(String(result.overallRisk).toUpperCase() + " risk"), {
    x: colLeft,
    y: panelBottom + 56,
    size: 12,
    font: ctx.helvBold,
    color: rcol,
  });
  ctx.page.drawText(sanitizePdfText("Overall risk level (letter grade in ring)"), {
    x: colLeft,
    y: panelBottom + 42,
    size: 10,
    font: ctx.helv,
    color: C.muted,
  });

  const barX = colLeft;
  const barW = CONTENT_W - (colLeft - MARGIN) - 12;
  const barH = 16;
  const barY = panelBottom + 22;
  ctx.page.drawRectangle({ x: barX, y: barY, width: barW, height: barH, color: C.surface2 });
  const fillW = (barW * Math.min(100, Math.max(0, result.score))) / 100;
  ctx.page.drawRectangle({ x: barX, y: barY, width: fillW, height: barH, color: rcol });
  ctx.page.drawText(sanitizePdfText(`Bar: ${result.score} / 100`), {
    x: barX + 6,
    y: barY + 3,
    size: 11,
    font: ctx.helvBold,
    color: C.ink,
  });

  ctx.page.drawText(sanitizePdfText("Higher score means fewer / less severe issues detected."), {
    x: colLeft,
    y: panelBottom + 8,
    size: 10,
    font: ctx.helv,
    color: C.muted,
  });
  ctx.y = panelBottom - 14;
}

function drawSeverityChart(ctx: DrawCtx, findings: CodeFinding[]): void {
  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const med = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low" || f.severity === "info").length;
  const total = Math.max(1, crit + high + med + low);
  ensureSpace(ctx, 48);
  const h = 22;
  const bottom = ctx.y - h - 12;
  ctx.page.drawText(sanitizePdfText("Findings by severity"), {
    x: MARGIN,
    y: bottom + h + 10,
    size: 14,
    font: ctx.helvBold,
    color: C.accentDark,
  });
  let x = MARGIN;
  const seg = (n: number, color: ReturnType<typeof rgb>, label: string) => {
    if (n <= 0) return;
    const w = Math.max((CONTENT_W * n) / total, 4);
    ctx.page.drawRectangle({ x, y: bottom, width: w, height: h, color });
    ctx.page.drawText(sanitizePdfText(`${label} ${n}`), {
      x: x + 4,
      y: bottom + 5,
      size: 10,
      font: ctx.helvBold,
      color: C.white,
    });
    x += w;
  };
  seg(crit, C.danger, "Crit");
  seg(high, rgb(0.98, 0.45, 0.2), "High");
  seg(med, C.warning, "Med");
  seg(low, C.info, "Low/Info");
  ctx.y = bottom - 8;
}

function drawFinding(ctx: DrawCtx, f: CodeFinding, index: number): void {
  const col = sevRgb(f.severity);
  const meta = `${f.category}${f.line != null ? ` | Line ${f.line}` : ""}${f.source ? ` | ${f.source}` : ""}`;
  drawLines(
    ctx,
    `${index}. [${f.severity.toUpperCase()}] ${f.title}\n   ${meta}`,
    12,
    true,
    col,
  );

  if (f.evidence) {
    drawLines(ctx, `Code preview: ${f.evidence}`, 11, false, rgb(0.2, 0.35, 0.55));
  }

  const vuln = f.vulnerability ?? f.description;
  const impact = f.impact ?? "";
  const rec = f.recommendation ?? f.fix ?? "";

  drawLines(ctx, `Vulnerability: ${vuln}`, 12, false, C.ink);
  drawLines(ctx, `Impact: ${impact}`, 12, false, C.muted);
  drawLines(ctx, `Recommendation: ${rec}`, 12, false, rgb(0.12, 0.42, 0.62));
  if (f.fix && f.fix !== rec) {
    drawLines(ctx, `Code hint: ${f.fix}`, 11, false, C.muted);
  }
  ctx.y -= 10;
}

export async function buildCodeReviewPdfBuffer(
  result: CodeReviewResult,
  opts?: { reportPreparedBy?: string | null },
): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.create();
  const helv = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const helvBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const page = pdfDoc.addPage([A4_W, A4_H]);
  const ctx: DrawCtx = { pdfDoc, page, y: A4_H - MARGIN, helv, helvBold };

  drawCover(ctx, result);
  const by = typeof opts?.reportPreparedBy === "string" ? opts.reportPreparedBy.trim() : "";
  if (by) {
    drawLines(ctx, `Report prepared by: ${by}`, 11, false, C.muted);
  }
  drawLines(ctx, "Executive summary", 14, true, C.accentDark);
  drawLines(ctx, result.summary, 12, false, C.ink);

  if (result.providerNote) {
    drawLines(ctx, `Note: ${result.providerNote}`, 11, false, C.info);
  }

  drawSeverityChart(ctx, result.findings);

  drawLines(ctx, "Detailed findings (simple English)", 14, true, C.accentDark);
  drawLines(
    ctx,
    "Each item lists the vulnerability, what can go wrong (impact), and what to do next. Review false positives in your real deployment context.",
    11,
    false,
    C.muted,
  );

  result.findings.forEach((f, i) => drawFinding(ctx, f, i + 1));

  if (result.recommendations.length > 0) {
    drawLines(ctx, "Next steps", 14, true, C.accentDark);
    result.recommendations.forEach((r, i) => {
      drawLines(ctx, `${i + 1}. ${r}`, 12, false, C.ink);
    });
  }

  const bytes = await pdfDoc.save();
  return bytes;
}
