import { NextRequest, NextResponse } from "next/server";
import { buildSecurityPdfBuffer } from "@/lib/build-security-pdf";
import { generatePdfNarrative } from "@/lib/pdf-narrative";
import { buildLibraryInventory } from "@/lib/library-inventory";
import { guardArgusRequest } from "@/lib/api-guard";
import { readJsonBodyLimited, validateSecurityPdfPayload } from "@/lib/pdf-payload-guard";
import { argusAudit } from "@/lib/argus-audit";
import type { AIReport, ScanResult, SSLResult } from "@/lib/types";
import type { MailAuthResult, SiteMetaResult } from "@/lib/mail-site-types";

export const runtime = "nodejs";

export async function POST(req: NextRequest) {
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const raw = await readJsonBodyLimited(req);
    if (raw instanceof NextResponse) return raw;
    const validated = validateSecurityPdfPayload(raw);
    if (validated instanceof NextResponse) return validated;
    const body = validated;
    const scan = body.scan as ScanResult;
    const ssl = body.ssl as SSLResult | undefined;
    const ai = body.ai as AIReport | undefined;
    const ports = body.ports as
      | {
          ip: string;
          ports: { port: number; service: string; exposureRisk?: string }[];
          cves?: string[];
          highRiskOpenPortsCount?: number;
        }
      | undefined;
    argusAudit("pdf_security_report", { hostname: scan.target?.hostname });

    const sa = body.sourceAudit as Record<string, unknown> | undefined;
    const libraryInventory =
      sa && !("error" in sa)
        ? buildLibraryInventory({
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
          })
        : null;

    const vt = body.virustotal as { analysis?: { verdict?: string } } | undefined;
    const takeoverN = body.takeover as { riskyCount?: number } | undefined;
    const narrativeBundle = {
      target: scan.target,
      score: scan.score,
      grade: scan.grade,
      headers: scan.headers,
      sslSummary: ssl ? { grade: ssl.grade, protocol: ssl.protocol } : null,
      portsSummary: ports
        ? { count: ports.ports?.length, highRisk: ports.highRiskOpenPortsCount }
        : null,
      secretsCount: Array.isArray(sa?.secretFindings) ? (sa!.secretFindings as unknown[]).length : 0,
      libraryInventorySummary: libraryInventory
        ? { passed: libraryInventory.passed, failed: libraryInventory.failed, warned: libraryInventory.warned }
        : null,
      virustotal: vt?.analysis ? { verdict: vt.analysis.verdict } : null,
      takeover: takeoverN ? { risky: takeoverN.riskyCount } : null,
      aiRisk: ai?.riskLevel,
    };

    const narrative = await generatePdfNarrative(narrativeBundle).catch(() => null);

    const reportPreparedBy =
      typeof body.reportPreparedBy === "string" ? body.reportPreparedBy : undefined;

    const mailAuth = body.mailAuth as MailAuthResult | undefined;
    const siteMeta = body.siteMeta as SiteMetaResult | undefined;
    const subdomains = body.subdomains as
      | { domain: string; count: number; subdomains: { subdomain: string; source: string }[] }
      | undefined;
    const googleDork = body.googleDork as Record<string, unknown> | undefined;

    const bytes = await buildSecurityPdfBuffer({
      scan,
      ssl,
      ai,
      ports,
      sourceAudit: body.sourceAudit as Record<string, unknown> | undefined,
      takeover: body.takeover as Record<string, unknown> | undefined,
      wpCron: body.wpCron as Record<string, unknown> | undefined,
      virustotal: body.virustotal as Record<string, unknown> | undefined,
      narrative,
      libraryInventory: libraryInventory?.items.length ? libraryInventory : null,
      mailAuth: mailAuth && typeof mailAuth.hostname === "string" ? mailAuth : null,
      siteMeta: siteMeta && typeof siteMeta.origin === "string" ? siteMeta : null,
      subdomains:
        subdomains && Array.isArray(subdomains.subdomains) && subdomains.subdomains.length > 0 ? subdomains : null,
      googleDork: googleDork && typeof googleDork === "object" ? googleDork : null,
      reportPreparedBy,
    });
    const host = typeof scan.target?.hostname === "string" ? scan.target.hostname : "report";
    const safe = host.replace(/[^\w.-]+/g, "_").slice(0, 80);

    return new NextResponse(Buffer.from(bytes), {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="argus-${safe}.pdf"`,
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "PDF generation failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
