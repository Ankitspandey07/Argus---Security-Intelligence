import net from "node:net";
import { NextRequest, NextResponse } from "next/server";
import { guardArgusRequest } from "@/lib/api-guard";
import { parseScanTargetOrError } from "@/lib/scan-target-policy";
import { argusAudit } from "@/lib/argus-audit";
import { analyzeVirusTotalDomainReport } from "@/lib/virustotal-analysis";

function sliceArr<T>(v: unknown, max: number): T[] | undefined {
  if (!Array.isArray(v)) return undefined;
  return (v as T[]).slice(0, max);
}

/** Single JSON blob for UI "full export" / manual analyst review */
function buildVtFullExport(hostname: string, data: Record<string, unknown>) {
  const whoisFull = typeof data.whois === "string" ? (data.whois as string) : "";
  return {
    _meta: {
      api: "VirusTotal v2 domain/report",
      domain: hostname,
      exportedAt: new Date().toISOString(),
      note: "Consolidated fields for manual verification in Argus. Larger limits than summary cards.",
    },
    response_code: data.response_code,
    verbose_msg: data.verbose_msg,
    categories: data.categories,
    Alexa_domain_info: data["Alexa domain info"],
    whois: whoisFull.length > 0 ? whoisFull.slice(0, 25000) : undefined,
    detected_urls: sliceArr<Record<string, unknown>>(data.detected_urls, 200),
    detected_communicating_samples: sliceArr<Record<string, unknown>>(data.detected_communicating_samples, 120),
    detected_downloaded_samples: sliceArr<Record<string, unknown>>(data.detected_downloaded_samples, 120),
    undetected_urls: sliceArr<Record<string, unknown>>(data.undetected_urls, 80),
    subdomains: sliceArr<string>(data.subdomains, 400),
    resolutions: sliceArr<Record<string, unknown>>(data.resolutions, 120),
    pcaps: sliceArr<Record<string, unknown>>(data.pcaps, 30),
  };
}

export async function POST(req: NextRequest) {
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const body = await req.json().catch(() => ({}));
    const inputUrl = body?.url;
    if (typeof inputUrl !== "string" || !inputUrl.trim()) {
      return NextResponse.json({ error: "URL or domain is required" }, { status: 400 });
    }
    const target = parseScanTargetOrError(inputUrl);
    if (target instanceof NextResponse) return target;
    const { hostname } = target;
    argusAudit("virustotal", { hostname });

    if (net.isIPv4(hostname) || net.isIPv6(hostname)) {
      return NextResponse.json({
        domain: hostname,
        skipped: true,
        message:
          "VirusTotal v2 domain/report applies to hostnames, not raw IPs. Scan a domain name, or use VT’s IP report in the GUI.",
      });
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY?.trim();
    if (!apiKey) {
      return NextResponse.json({
        skipped: true,
        message: "VIRUSTOTAL_API_KEY not set. Add it to .env.local for domain reputation.",
        domain: hostname,
      });
    }

    /** VT v2 OpenAPI: GET /domain/report?apikey=&domain= (POST form is not supported for this endpoint). */
    const vtUrl = new URL("https://www.virustotal.com/vtapi/v2/domain/report");
    vtUrl.searchParams.set("apikey", apiKey);
    vtUrl.searchParams.set("domain", hostname);
    const res = await fetch(vtUrl.toString(), {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(25000),
    });
    let data: Record<string, unknown>;
    try {
      data = (await res.json()) as Record<string, unknown>;
    } catch {
      return NextResponse.json(
        { domain: hostname, skipped: false, error: "VirusTotal returned a non-JSON response." },
        { status: 502 },
      );
    }

    if (!res.ok) {
      return NextResponse.json({
        domain: hostname,
        skipped: false,
        error: `VirusTotal HTTP ${res.status}`,
        vtFullExport: { _meta: { domain: hostname, error: true }, raw: data },
      });
    }

    if (typeof data.response_code === "number" && data.response_code !== 1) {
      return NextResponse.json({
        domain: hostname,
        skipped: false,
        error: (data.verbose_msg as string) || "No report for this domain (response_code !== 1)",
        vtFullExport: buildVtFullExport(hostname, data),
      });
    }

    const detectedUrls = sliceArr<Record<string, unknown>>(data.detected_urls, 200);
    const detectedCommunicatingSamples = sliceArr<Record<string, unknown>>(data.detected_communicating_samples, 120);
    const detectedDownloadedSamples = sliceArr<Record<string, unknown>>(data.detected_downloaded_samples, 120);
    const subdomains = sliceArr<string>(data.subdomains, 400);
    const whoisSlice = typeof data.whois === "string" ? (data.whois as string).slice(0, 12000) : undefined;

    const analysis = analyzeVirusTotalDomainReport({
      categories: data.categories,
      detectedUrls,
      detectedCommunicatingSamples,
      detectedDownloadedSamples,
      subdomains,
      whois: whoisSlice,
    });

    const positives = Array.isArray(detectedUrls)
      ? detectedUrls.reduce((acc, u) => acc + Number((u as { positives?: number }).positives || 0), 0)
      : undefined;

    const vtFullExport = buildVtFullExport(hostname, data);

    return NextResponse.json({
      domain: hostname,
      responseCode: data.response_code,
      categories: data.categories,
      subdomains: subdomains?.slice(0, 120),
      detectedUrls: detectedUrls?.slice(0, 40),
      detectedCommunicatingSamples: detectedCommunicatingSamples?.slice(0, 25),
      detectedDownloadedSamples: detectedDownloadedSamples?.slice(0, 25),
      resolutions: sliceArr<Record<string, unknown>>(data.resolutions, 15),
      whois: whoisSlice,
      Alexa: data["Alexa domain info"],
      undetectedUrls: sliceArr<Record<string, unknown>>(data.undetected_urls, 15),
      pcaps: sliceArr<Record<string, unknown>>(data.pcaps, 5),
      analysis,
      vtFullExport,
      summary: {
        note: "VirusTotal v2 domain report — use vtFullExport for full analyst JSON.",
        detectedUrlPositiveHits: positives,
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "VirusTotal request failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
