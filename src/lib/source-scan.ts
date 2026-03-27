import { SECRET_PATTERNS, redactMatch } from "./secret-patterns";
import { decodeJwtParts } from "./jwt-decode";

export interface SecretFinding {
  patternId: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  sourceUrl: string;
  redacted: string;
  hint: string;
  /** 1-based line in the scanned file (HTML page or .js URL or inline block) */
  lineNumber?: number;
  /** 1-based column (approximate start of match) */
  columnApprox?: number;
  /** Surrounding text with the secret removed — use this to Ctrl+F in Sources / View Source */
  contextSnippet?: string;
  /** How to locate the match in DevTools or source view */
  locateHint?: string;
  jwtDecoded?: { header: unknown; payload: unknown };
}

const PATTERN_SEARCH_KEYS: Record<string, string> = {
  aws_access_key: "AKIA",
  aws_temp_key: "ASIA",
  google_api_key: "AIza",
  github_token: "ghp_ or github_pat",
  stripe_live: "sk_live",
  stripe_test: "sk_test",
  openai_sk: "sk-",
  generic_api_assignment: "apiKey, secret, or token =",
  jwt_bearer: "eyJ",
  mongodb_uri: "mongodb://",
  postgres_uri: "postgres:// or mysql://",
  firebase: "firebaseio.com",
  slack_token: "xox",
  private_key_block: "BEGIN PRIVATE KEY",
};

function buildContextSnippet(text: string, matchStart: number, matchEnd: number, pad = 120): string {
  const a = Math.max(0, matchStart - pad);
  const b = Math.min(text.length, matchEnd + pad);
  const before = text.slice(a, matchStart).replace(/\s+/g, " ").trim();
  const after = text.slice(matchEnd, b).replace(/\s+/g, " ").trim();
  const clip = (s: string, max: number) => (s.length > max ? `…${s.slice(-max)}` : s);
  const beforeShow = clip(before, pad);
  const afterShow = after.length > 80 ? `${after.slice(0, 80)}…` : after;
  return `${beforeShow} [SECRET_REDACTED] ${afterShow}`.trim();
}

function locateHintFor(patternId: string, sourceUrl: string, lineNumber: number): string {
  const key = PATTERN_SEARCH_KEYS[patternId] || "substring from snippet";
  if (/\(inline script/i.test(sourceUrl)) {
    return `Open the page → View Page Source (Ctrl/Cmd+U) → search for “${key}” or text from the snippet. Inline block: ${sourceUrl}. Approximate line in that block: ${lineNumber}. Or DevTools → Elements → search (Ctrl+F) in HTML.`;
  }
  if (/\.js(\?|$)/i.test(sourceUrl) || /\/[^/]+\.js\b/i.test(sourceUrl)) {
    return `Open this script URL directly. Chrome DevTools → Sources → open file → Ctrl/Cmd+G → line ${lineNumber}. Or Ctrl/Cmd+F and search “${key}” or words from the snippet before/after [SECRET_REDACTED].`;
  }
  return `View source of the page (Ctrl/Cmd+U), go to ~line ${lineNumber}, or search for “${key}” / distinctive words from the snippet.`;
}

export function scanTextForSecrets(text: string, sourceUrl: string, maxFindings = 80): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const seen = new Set<string>();

  for (const p of SECRET_PATTERNS) {
    const flags = p.regex.flags.includes("g") ? p.regex.flags : `${p.regex.flags}g`;
    const re = new RegExp(p.regex.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const raw = (m[1] !== undefined ? m[1] : m[0]).trim();
      if (raw.length < 6) continue;

      const matchStart = m.index;
      const matchEnd = matchStart + m[0].length;
      const lineNumber = text.slice(0, matchStart).split("\n").length;
      const lastNl = text.lastIndexOf("\n", matchStart);
      const columnApprox = matchStart - (lastNl === -1 ? 0 : lastNl + 1) + 1;

      const key = `${p.id}:${raw.slice(0, 24)}:${sourceUrl}:${lineNumber}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const finding: SecretFinding = {
        patternId: p.id,
        label: p.label,
        severity: p.severity,
        sourceUrl,
        redacted: redactMatch(raw),
        hint: p.hint,
        lineNumber,
        columnApprox,
        contextSnippet: buildContextSnippet(text, matchStart, matchEnd),
        locateHint: locateHintFor(p.id, sourceUrl, lineNumber),
      };

      if (p.id === "jwt_bearer" || raw.startsWith("eyJ")) {
        const dec = decodeJwtParts(raw);
        if (dec) finding.jwtDecoded = { header: dec.header, payload: dec.payload };
      }

      findings.push(finding);
      if (findings.length >= maxFindings) return findings;

      if (m[0].length === 0) re.lastIndex++;
    }
  }

  return findings;
}

export function extractScriptSrcs(html: string, base: URL): string[] {
  const out: string[] = [];
  const re = /<script[^>]*\ssrc=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    try {
      const u = new URL(m[1], base);
      if (u.protocol === "http:" || u.protocol === "https:") out.push(u.href);
    } catch { /* skip */ }
  }
  return [...new Set(out)];
}

export function extractHtmlPageUrls(html: string, base: URL, max = 40): string[] {
  const out: string[] = [];
  const patterns = [
    /<a[^>]+href=["']([^"']+)["']/gi,
    /<link[^>]+href=["']([^"']+)["']/gi,
    /<form[^>]+action=["']([^"']+)["']/gi,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      try {
        const u = new URL(m[1], base);
        if (u.hostname !== base.hostname) continue;
        if (!["http:", "https:"].includes(u.protocol)) continue;
        const path = u.pathname.toLowerCase();
        if (path.endsWith(".css") || path.endsWith(".ico") || path.endsWith(".png") || path.endsWith(".jpg")) continue;
        out.push(u.href.split("#")[0]);
      } catch { /* skip */ }
    }
  }
  return [...new Set(out)].slice(0, max);
}

export function extractInlineScripts(html: string): string[] {
  const blocks: string[] = [];
  const re = /<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const body = m[1].trim();
    if (body.length > 20) blocks.push(body);
  }
  return blocks;
}
