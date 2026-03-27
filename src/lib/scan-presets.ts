/** Presets for public hosting: no DB — only which modules run per scan. */

export type ScanPreset = "quick" | "complete";

const ALL_MODULE_IDS = [
  "headers",
  "source",
  "ssl",
  "mailAuth",
  "siteMeta",
  "subdomains",
  "ports",
  "virustotal",
  "wpcron",
  "googleDork",
  "takeover",
  "tech",
  "ai",
] as const;

export type ScanModuleId = (typeof ALL_MODULE_IDS)[number];

/** Quick: fast checks only — good for demos and free-tier rate limits (no crawl, AI, or third-party search). */
const QUICK = new Set<string>([
  "headers",
  "ssl",
  "mailAuth",
  "siteMeta",
  "ports",
  "takeover",
  "tech",
]);

/** Complete: all modules (source crawl, subdomains, VT, etc.). */
const COMPLETE = new Set<string>(ALL_MODULE_IDS);

export function moduleIdsForPreset(preset: ScanPreset): Set<string> {
  return preset === "quick" ? QUICK : COMPLETE;
}

export function shouldRunModule(preset: ScanPreset, id: string): boolean {
  return moduleIdsForPreset(preset).has(id);
}

export const SCAN_MODULE_LIST: { id: ScanModuleId; label: string }[] = [
  { id: "headers", label: "Headers & cookies" },
  { id: "source", label: "Source & secrets" },
  { id: "ssl", label: "SSL / TLS" },
  { id: "mailAuth", label: "Mail auth (SPF / DMARC)" },
  { id: "siteMeta", label: "robots.txt & security.txt" },
  { id: "subdomains", label: "Subdomains" },
  { id: "ports", label: "Ports & CVEs" },
  { id: "virustotal", label: "VirusTotal" },
  { id: "wpcron", label: "WP / infra exposure" },
  { id: "googleDork", label: "Google dork" },
  { id: "takeover", label: "Takeover (apex quick)" },
  { id: "tech", label: "Stack fingerprint" },
  { id: "ai", label: "AI report" },
];

export function modulesForProgress(preset: ScanPreset): { id: string; label: string }[] {
  return SCAN_MODULE_LIST.filter((m) => shouldRunModule(preset, m.id));
}
