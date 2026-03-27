import { NextRequest, NextResponse } from "next/server";
import { guardArgusRequest } from "@/lib/api-guard";
import { parseScanTargetOrError } from "@/lib/scan-target-policy";
import { argusAudit } from "@/lib/argus-audit";
import {
  scanTextForSecrets,
  extractScriptSrcs,
  extractHtmlPageUrls,
  extractInlineScripts,
} from "@/lib/source-scan";
import { auditScriptUrls } from "@/lib/library-risks";
import { matchRetireForScripts } from "@/lib/retire-match";
import { extractLibraryVersionsFromJs } from "@/lib/js-library-versions";
import { probeAwsLeakyPaths, filterAwsRelatedSecretFindings } from "@/lib/aws-leak-scan";
import { PRIMARY_SCAN_FETCH_HEADERS } from "@/lib/scanner-fetch-headers";
const MAX_HTML_PAGES = 18;
const MAX_JS_FILES = 22;
const FETCH_TIMEOUT_MS = 12000;
const MAX_BODY_CHARS = 400_000;
const MAX_SCRIPT_URLS_RETURN = 200;

async function fetchText(url: string): Promise<{ ok: boolean; status: number; text: string; error?: string }> {
  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: {
        ...PRIMARY_SCAN_FETCH_HEADERS,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
    const buf = await res.arrayBuffer();
    const text = new TextDecoder("utf-8", { fatal: false }).decode(buf).slice(0, MAX_BODY_CHARS);
    return { ok: res.ok, status: res.status, text };
  } catch (e: unknown) {
    return { ok: false, status: 0, text: "", error: e instanceof Error ? e.message : "fetch failed" };
  }
}

export async function POST(req: NextRequest) {
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const body = await req.json().catch(() => ({}));
    const inputUrl = body?.url;
    const maxPages = body?.maxPages ?? MAX_HTML_PAGES;
    if (typeof inputUrl !== "string" || !inputUrl.trim()) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 });
    }

    const parsed = parseScanTargetOrError(inputUrl);
    if (parsed instanceof NextResponse) return parsed;
    const { url } = parsed;
    argusAudit("source_audit", { hostname: parsed.hostname });
    const base = new URL(url);
    if (!base.pathname || base.pathname === "") base.pathname = "/";

    const pagesVisited: string[] = [];
    const scriptUrlsSeen = new Set<string>();
    const allFindings: ReturnType<typeof scanTextForSecrets> = [];
    const pageErrors: { url: string; error: string }[] = [];

    const queue: string[] = [base.href];
    const visited = new Set<string>();

    while (queue.length > 0 && pagesVisited.length < Math.min(Number(maxPages) || MAX_HTML_PAGES, MAX_HTML_PAGES)) {
      const pageUrl = queue.shift()!;
      const key = pageUrl.split("#")[0];
      if (visited.has(key)) continue;
      visited.add(key);

      const { ok, text, error, status } = await fetchText(key);
      if (!ok && !text) {
        pageErrors.push({ url: key, error: error || `HTTP ${status}` });
        continue;
      }
      const looksHtml = /<\s*html|<!DOCTYPE|<\s*head|<\s*body/i.test(text.slice(0, 8000));
      if (!text || !looksHtml) {
        if (status >= 400) pageErrors.push({ url: key, error: `HTTP ${status}` });
        continue;
      }

      pagesVisited.push(key);
      allFindings.push(...scanTextForSecrets(text, key));

      const inlineBlocks = extractInlineScripts(text);
      for (let ib = 0; ib < inlineBlocks.length; ib++) {
        allFindings.push(
          ...scanTextForSecrets(inlineBlocks[ib], `${key} (inline script #${ib + 1})`),
        );
      }

      const scripts = extractScriptSrcs(text, base);
      for (const su of scripts) scriptUrlsSeen.add(su);

      const nextUrls = extractHtmlPageUrls(text, base, 30);
      for (const u of nextUrls) {
        if (!visited.has(u) && !queue.includes(u)) queue.push(u);
      }
    }

    let jsFetched = 0;
    const jsContents: { url: string; body: string }[] = [];
    for (const jsUrl of scriptUrlsSeen) {
      if (jsFetched >= MAX_JS_FILES) break;
      const { text: js, ok } = await fetchText(jsUrl);
      if (!ok && !js) continue;
      jsFetched++;
      allFindings.push(...scanTextForSecrets(js, jsUrl));
      if (js.length > 0) jsContents.push({ url: jsUrl, body: js });
    }

    const libraryRisks = auditScriptUrls([...scriptUrlsSeen]);
    const retireMatches = await matchRetireForScripts([...scriptUrlsSeen], jsContents);

    const detectedJsLibraries: { library: string; version: string; url: string; evidence: string }[] = [];
    const libSeen = new Set<string>();
    for (const { url, body } of jsContents) {
      for (const hit of extractLibraryVersionsFromJs(body, url)) {
        const k = `${hit.library}:${hit.version}:${url}`;
        if (libSeen.has(k)) continue;
        libSeen.add(k);
        detectedJsLibraries.push({
          library: hit.library,
          version: hit.version,
          url,
          evidence: hit.evidence,
        });
      }
    }
    for (const u of scriptUrlsSeen) {
      for (const hit of extractLibraryVersionsFromJs("", u)) {
        const k = `${hit.library}:${hit.version}:${u}`;
        if (libSeen.has(k)) continue;
        libSeen.add(k);
        detectedJsLibraries.push({
          library: hit.library,
          version: hit.version,
          url: u,
          evidence: hit.evidence,
        });
      }
    }

    const dedupe = new Map<string, (typeof allFindings)[0]>();
    for (const f of allFindings) {
      const k = `${f.patternId}:${f.redacted}:${f.sourceUrl}:${f.lineNumber ?? 0}`;
      if (!dedupe.has(k)) dedupe.set(k, f);
    }
    const findings = [...dedupe.values()];

    const awsSecretFindings = filterAwsRelatedSecretFindings(findings);
    const awsProbes = await probeAwsLeakyPaths(base.origin);
    const awsProbeSignals = awsProbes.filter((p) => p.signal === "aws_signal").length;

    return NextResponse.json({
      baseUrl: base.origin,
      pagesCrawled: pagesVisited.length,
      pages: pagesVisited,
      scriptUrlsSample: [...scriptUrlsSeen].slice(0, 40),
      scriptUrls: [...scriptUrlsSeen].slice(0, MAX_SCRIPT_URLS_RETURN),
      detectedJsLibraries,
      secretFindings: findings,
      libraryRisks,
      retireMatches,
      pageErrors: pageErrors.slice(0, 15),
      summary: {
        critical: findings.filter((f) => f.severity === "critical").length,
        high: findings.filter((f) => f.severity === "high").length,
        medium: findings.filter((f) => f.severity === "medium").length,
        low: findings.filter((f) => f.severity === "low").length,
      },
      awsLeakScan: {
        secretFindings: awsSecretFindings,
        probes: awsProbes,
        probeSignalCount: awsProbeSignals,
        note:
          "AWS section: patterns in crawled HTML/JS (AKIA/ASIA/…) plus HTTP probes for common config URLs. Confirm manually; probes can false-positive on tutorials.",
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Source audit failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
