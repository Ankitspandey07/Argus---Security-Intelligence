import type { ScanResult } from "@/lib/types";

export type LibraryInventoryStatus = "pass" | "warn" | "fail";

export interface LibraryInventoryItem {
  id: string;
  name: string;
  version: string | null;
  source: "technology" | "javascript" | "heuristic";
  status: LibraryInventoryStatus;
  detail: string;
  referenceUrl?: string;
}

export interface LibraryInventoryResult {
  items: LibraryInventoryItem[];
  passed: number;
  failed: number;
  warned: number;
  explanation: string;
}

function norm(s: string): string {
  return s.toLowerCase().replace(/\s+/g, " ").trim();
}

function keyFor(name: string, version: string | null): string {
  return `${norm(name)}::${version || "?"}`;
}

/** Merge Wappalyzer-style technologies + JS detections + risks + Retire CVE hits. */
export function buildLibraryInventory(args: {
  scan?: ScanResult;
  scriptUrls?: string[];
  detectedJsLibraries?: { library: string; version: string; url: string; evidence: string }[];
  libraryRisks?: { library: string; version: string | null; severity: string; note: string; url: string }[];
  retireMatches?: {
    library: string;
    version: string;
    scriptUrl: string;
    summary: string;
    cves: string[];
  }[];
}): LibraryInventoryResult {
  const items: LibraryInventoryItem[] = [];
  const byKey = new Map<string, LibraryInventoryItem>();

  const upsert = (
    name: string,
    version: string | null,
    source: LibraryInventoryItem["source"],
    status: LibraryInventoryStatus,
    detail: string,
    referenceUrl?: string,
  ) => {
    const k = keyFor(name, version);
    const worse = (a: LibraryInventoryStatus, b: LibraryInventoryStatus) => {
      const o = { fail: 3, warn: 2, pass: 1 };
      return o[a] >= o[b] ? a : b;
    };
    const existing = byKey.get(k);
    if (existing) {
      existing.status = worse(existing.status, status);
      if (detail.length > existing.detail.length) existing.detail = detail;
      if (referenceUrl && !existing.referenceUrl) existing.referenceUrl = referenceUrl;
      return;
    }
    const item: LibraryInventoryItem = {
      id: k,
      name,
      version,
      source,
      status,
      detail,
      referenceUrl,
    };
    byKey.set(k, item);
    items.push(item);
  };

  const retire = args.retireMatches || [];
  const failSet = new Set(retire.map((r) => keyFor(r.library, r.version)));

  for (const r of retire) {
    upsert(
      r.library,
      r.version,
      "javascript",
      "fail",
      `Matched Retire.js CVE ranges: ${(r.cves || []).join(", ") || "known vulnerable lineage"}. ${r.summary}`,
      r.scriptUrl,
    );
  }

  for (const lr of args.libraryRisks || []) {
    const k = keyFor(lr.library, lr.version);
    if (failSet.has(k)) continue;
    upsert(
      lr.library,
      lr.version,
      "heuristic",
      "warn",
      lr.note,
      lr.url,
    );
  }

  for (const d of args.detectedJsLibraries || []) {
    const k = keyFor(d.library, d.version);
    if (failSet.has(k)) continue;
    const hasWarn = (args.libraryRisks || []).some(
      (lr) => norm(lr.library) === norm(d.library) && (!lr.version || lr.version === d.version),
    );
    upsert(
      d.library,
      d.version,
      "javascript",
      hasWarn ? "warn" : "pass",
      hasWarn
        ? `Detected in scripts (${d.evidence}); URL heuristics also flagged risk.`
        : `Detected from fetched scripts or CDN paths (${d.evidence}). No Retire CVE match for this version in our database snapshot.`,
      d.url,
    );
  }

  const techs = args.scan?.technologies || [];
  for (const t of techs) {
    const v = t.version || null;
    const k = keyFor(t.name, v);
    if (failSet.has(k)) continue;
    const already = byKey.has(k);
    if (already) continue;

    const n = norm(t.name);
    let status: LibraryInventoryStatus = "pass";
    let detail = `Observed via passive fingerprinting (${t.category || "stack"}).`;
    if (n.includes("angularjs") || (n.includes("angular") && n.includes("js") && v?.startsWith("1."))) {
      status = "warn";
      detail = "AngularJS 1.x is end-of-life; plan migration even if no automatic CVE matched.";
    }
    if (n.includes("jquery") && v) {
      const major = parseInt(v.split(".")[0], 10);
      if (!Number.isNaN(major) && major < 3) {
        status = "warn";
        detail = "jQuery 1.x/2.x are outdated lineages — review for XSS fixes and upgrade path.";
      }
    }
    upsert(t.name, v, "technology", status, detail);
  }

  /** Script URLs that imply libraries not yet in list (lightweight path hints). */
  const hints: { name: string; rx: RegExp }[] = [
    { name: "Google Analytics / gtag", rx: /google-analytics\.com|googletagmanager\.com|gtag/i },
    { name: "Facebook Pixel", rx: /connect\.facebook\.net/i },
    { name: "reCAPTCHA", rx: /recaptcha|google\.com\/recaptcha/i },
    { name: "Stripe.js", rx: /js\.stripe\.com/i },
    { name: "Sentry", rx: /sentry\.io|browser\.sentry-cdn/i },
    { name: "DataDog RUM", rx: /datadoghq\.com|datadog-browser/i },
  ];
  for (const url of args.scriptUrls || []) {
    for (const h of hints) {
      if (!h.rx.test(url)) continue;
      const k = keyFor(h.name, null);
      if (byKey.has(k)) continue;
      upsert(h.name, null, "javascript", "pass", "Third-party script endpoint referenced from the page (inventory only).", url);
    }
  }

  const passed = items.filter((i) => i.status === "pass").length;
  const failed = items.filter((i) => i.status === "fail").length;
  const warned = items.filter((i) => i.status === "warn").length;
  const total = items.length;

  const explanation =
    total === 0
      ? "No libraries cataloged in this crawl sample."
      : `Inventory: ${passed} ok · ${failed} CVE match · ${warned} warn`;

  return { items, passed, failed, warned, explanation };
}
