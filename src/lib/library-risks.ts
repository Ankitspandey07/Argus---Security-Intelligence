/**
 * Retire.js–style heuristics from script URL paths (no full Retire DB bundled).
 * Versions below `safeMin` are flagged as using known-vulnerable lineages.
 */

export interface LibraryRule {
  name: string;
  pathRegex: RegExp;
  extractVersion: (path: string) => string | null;
  safeMin: [number, number, number];
  cveNote: string;
  severity: "critical" | "high" | "medium";
}

function parseSemver(s: string): [number, number, number] | null {
  const m = s.match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3] || "0", 10)];
}

function lt(a: [number, number, number], b: [number, number, number]): boolean {
  if (a[0] !== b[0]) return a[0] < b[0];
  if (a[1] !== b[1]) return a[1] < b[1];
  return a[2] < b[2];
}

export const LIBRARY_RULES: LibraryRule[] = [
  {
    name: "jQuery",
    pathRegex: /jquery(?:\.min)?\.js|jquery-(\d+\.\d+\.\d+)|jquery\/(\d+\.\d+\.\d+)/i,
    extractVersion: (p) => {
      const m = p.match(/jquery-(\d+\.\d+\.\d+)/i) || p.match(/jquery\/(\d+\.\d+\.\d+)/i);
      return m ? m[1] : null;
    },
    safeMin: [3, 5, 0],
    cveNote: "jQuery <3.5.0 — XSS in HTML manipulation (CVE-2020-11022 / CVE-2020-11023); older 1.x/2.x EOL",
    severity: "high",
  },
  {
    name: "AngularJS (1.x)",
    pathRegex: /angular(?:\.min)?\.js|angularjs/i,
    extractVersion: (p) => {
      const m = p.match(/angular-?(\d+\.\d+\.\d+)/i);
      return m ? m[1] : "1.x";
    },
    safeMin: [2, 0, 0],
    cveNote: "AngularJS 1.x is EOL; multiple XSS / sandbox issues over time",
    severity: "high",
  },
  {
    name: "Bootstrap",
    pathRegex: /bootstrap(?:\.min)?\.(?:js|css)/i,
    extractVersion: (p) => {
      const m = p.match(/bootstrap[/-](\d+\.\d+\.\d+)/i);
      return m ? m[1] : null;
    },
    safeMin: [5, 0, 0],
    cveNote: "Bootstrap 3.x/4.x older builds — check XSS in data attributes / tooltips",
    severity: "medium",
  },
  {
    name: "Lodash",
    pathRegex: /lodash(?:\.min)?\.js|lodash-core/i,
    extractVersion: (p) => {
      const m = p.match(/lodash[/-](\d+\.\d+\.\d+)/i);
      return m ? m[1] : null;
    },
    safeMin: [4, 17, 21],
    cveNote: "Lodash <4.17.21 — prototype pollution (CVE-2020-8203, CVE-2021-23337)",
    severity: "high",
  },
];

export function auditScriptUrls(urls: string[]): { library: string; version: string | null; severity: string; note: string; url: string }[] {
  const out: { library: string; version: string | null; severity: string; note: string; url: string }[] = [];
  for (const url of urls) {
    const lower = url.toLowerCase();
    for (const rule of LIBRARY_RULES) {
      if (!rule.pathRegex.test(url)) continue;
      const v = rule.extractVersion(url);
      const semver = v ? parseSemver(v) : null;
      const isOld = semver ? lt(semver, rule.safeMin) : /jquery-1\.|jquery-2\.|angular\.js|angularjs/i.test(lower);
      if (isOld || (v === "1.x" && rule.name.includes("Angular"))) {
        out.push({
          library: rule.name,
          version: v,
          severity: rule.severity,
          note: rule.cveNote,
          url,
        });
      }
    }
  }
  return out;
}
