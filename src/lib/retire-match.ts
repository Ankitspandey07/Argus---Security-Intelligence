import semver from "semver";
import { extractLibraryVersionsFromJs } from "@/lib/js-library-versions";

const RETIRE_URL =
  "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json";

let cache: { data: Record<string, RetireLibraryEntry>; expires: number } | null = null;
const TTL_MS = 60 * 60 * 1000;

interface RetireVuln {
  below?: string;
  atOrAbove?: string;
  above?: string;
  identifiers?: { CVE?: string[]; summary?: string; bug?: string };
  info?: string[];
  summary?: string;
}

interface RetireLibraryEntry {
  vulnerabilities?: RetireVuln[];
}

async function loadRepository(): Promise<Record<string, RetireLibraryEntry> | null> {
  const now = Date.now();
  if (cache && cache.expires > now) return cache.data;

  try {
    const res = await fetch(RETIRE_URL, { signal: AbortSignal.timeout(45000) });
    if (!res.ok) return cache?.data ?? null;
    const data = (await res.json()) as Record<string, RetireLibraryEntry>;
    cache = { data, expires: now + TTL_MS };
    return data;
  } catch {
    return cache?.data ?? null;
  }
}

function urlMentionsLibrary(url: string, libKey: string): boolean {
  const u = url.toLowerCase();
  const k = libKey.toLowerCase();
  if (k === "jquery") return /\/jquery([@/-]|\.min\.js)/i.test(u) && !/jquerymobile/i.test(u);
  if (k === "angularjs" || k === "angular.js")
    return /angular(\.min)?\.js/i.test(u) || /\/angular\.js/i.test(u) || /angularjs/i.test(u);
  return u.includes(`/${k}/`) || u.includes(`/${k}.`) || u.includes(`@${k}/`) || u.includes(`${k}-`);
}

function npmNameToRetireKey(pkg: string): string {
  const p = pkg.toLowerCase().replace(/\.min$/, "").replace(/\.js$/, "");
  const map: Record<string, string> = {
    jquery: "jquery",
    angular: "angularjs",
    "angular.js": "angularjs",
    lodash: "lodash",
    moment: "moment",
    vue: "vue",
    axios: "axios",
    bootstrap: "bootstrap",
    "twitter-bootstrap": "bootstrap",
    handlebars: "handlebars",
    underscore: "underscore",
    dompurify: "dompurify",
  };
  return map[p] || p;
}

function extractVersionFromUrl(url: string, libKey: string): string | null {
  const u = url;
  const k = libKey.replace(/\./g, "\\.");
  const want = libKey.toLowerCase();

  const cdnUnpkg = url.match(/unpkg\.com\/(?:@[^/]+\/)?([^/@]+)@(\d+\.\d+[^/?#]*)/i);
  if (cdnUnpkg && npmNameToRetireKey(cdnUnpkg[1]) === want) {
    const c = semver.coerce(cdnUnpkg[2]);
    return c ? c.version : cdnUnpkg[2];
  }

  const cdnJsdelivr = url.match(/cdn\.jsdelivr\.net\/npm\/(?:@[^/]+\/)?([^/@]+)@(\d+\.\d+[^/?#]*)/i);
  if (cdnJsdelivr && npmNameToRetireKey(cdnJsdelivr[1]) === want) {
    const c = semver.coerce(cdnJsdelivr[2]);
    return c ? c.version : cdnJsdelivr[2];
  }

  const cdnjs = url.match(/cdnjs\.cloudflare\.com\/ajax\/libs\/([^/]+)\/(\d+\.\d+[^/]*)\//i);
  if (cdnjs && npmNameToRetireKey(cdnjs[1]) === want) {
    const c = semver.coerce(cdnjs[2]);
    return c ? c.version : cdnjs[2];
  }

  const patterns = [
    new RegExp(`/${k}/(\\d+\\.\\d+\\.?\\d*)`, "i"),
    new RegExp(`${k}[@\\-](\\d+\\.\\d+\\.?\\d*)`, "i"),
    new RegExp(`${k}\\.(\\d+\\.\\d+\\.?\\d*)\\.min\\.js`, "i"),
    new RegExp(`-${k}-(\\d+\\.\\d+\\.?\\d*)`, "i"),
  ];
  for (const re of patterns) {
    const m = u.match(re);
    if (m?.[1]) {
      const c = semver.coerce(m[1]);
      return c ? c.version : m[1];
    }
  }
  const loose = url.match(/(\d+\.\d+\.\d+)/);
  if (loose && urlMentionsLibrary(url, libKey)) {
    const c = semver.coerce(loose[1]);
    return c ? c.version : loose[1];
  }
  return null;
}

function isVulnerable(version: string, v: RetireVuln): boolean {
  const coerced = semver.coerce(version);
  if (!coerced) return false;
  if (v.below) {
    const b = semver.coerce(v.below);
    if (b && semver.lt(coerced, b)) {
      if (v.atOrAbove) {
        const a = semver.coerce(v.atOrAbove);
        if (a && semver.lt(coerced, a)) return false;
      }
      if (v.above) {
        const a = semver.coerce(v.above);
        if (a && !semver.gt(coerced, a)) return false;
      }
      return true;
    }
  }
  return false;
}

export interface RetireMatch {
  library: string;
  version: string;
  scriptUrl: string;
  cves: string[];
  summary: string;
  references: string[];
  /** Whether version was parsed from URL or from fetched JS body / CDN path */
  detectionSource?: "url" | "content";
}

function collectMatchesForLib(
  repo: Record<string, RetireLibraryEntry>,
  libKey: string,
  version: string,
  scriptUrl: string,
  detectionSource: "url" | "content",
  hits: RetireMatch[],
  seen: Set<string>,
): void {
  const entry = repo[libKey];
  if (!entry || typeof entry !== "object") return;
  const vulns = entry.vulnerabilities;
  if (!Array.isArray(vulns) || vulns.length === 0) return;

  for (const v of vulns) {
    if (!isVulnerable(version, v)) continue;
    const cves = v.identifiers?.CVE ?? [];
    const summary =
      v.identifiers?.summary || v.summary || v.identifiers?.bug || "Known vulnerable version per Retire.js";
    const references = Array.isArray(v.info) ? v.info : [];
    const key = `${libKey}:${version}:${scriptUrl}:${cves.join(",")}:${detectionSource}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hits.push({
      library: libKey,
      version,
      scriptUrl,
      cves,
      summary,
      references,
      detectionSource,
    });
  }
}

/**
 * Match script URLs and optional fetched JS bodies against Retire.js CVE database.
 */
export async function matchRetireForScripts(
  scriptUrls: string[],
  jsContents: { url: string; body: string }[] = [],
): Promise<RetireMatch[]> {
  const repo = await loadRepository();
  if (!repo) return [];

  const hits: RetireMatch[] = [];
  const seen = new Set<string>();

  for (const url of scriptUrls) {
    for (const libKey of Object.keys(repo)) {
      if (libKey.startsWith("_") || libKey === "version") continue;
      if (!urlMentionsLibrary(url, libKey)) continue;
      const version = extractVersionFromUrl(url, libKey);
      if (!version) continue;
      collectMatchesForLib(repo, libKey, version, url, "url", hits, seen);
    }
  }

  for (const { url, body } of jsContents) {
    const fromBody = extractLibraryVersionsFromJs(body, url);
    for (const det of fromBody) {
      const libKey = det.library;
      if (!repo[libKey] || libKey.startsWith("_")) continue;
      collectMatchesForLib(repo, libKey, det.version, url, "content", hits, seen);
    }
  }

  return hits;
}

export async function matchRetireForScriptUrls(scriptUrls: string[]): Promise<RetireMatch[]> {
  return matchRetireForScripts(scriptUrls, []);
}
