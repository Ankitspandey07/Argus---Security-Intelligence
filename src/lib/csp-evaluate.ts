/**
 * Lightweight CSP policy string analysis (not a full CSP3 validator).
 */

export type CspIssueSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface CspIssue {
  id: string;
  severity: CspIssueSeverity;
  title: string;
  detail: string;
}

function directivesFrom(raw: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  const s = raw.replace(/\s+/g, " ").trim();
  if (!s) return map;
  for (const part of s.split(";")) {
    const p = part.trim();
    if (!p) continue;
    const sp = p.split(/\s+/);
    const name = sp[0]?.toLowerCase();
    if (!name) continue;
    const values = sp.slice(1).filter(Boolean);
    map.set(name, values);
  }
  return map;
}

export function evaluateContentSecurityPolicy(raw: string | undefined | null): {
  present: boolean;
  score: number;
  summary: string;
  issues: CspIssue[];
} {
  if (!raw || !String(raw).trim()) {
    return {
      present: false,
      score: 0,
      summary: "No Content-Security-Policy header — XSS and injection rely only on other layers.",
      issues: [
        {
          id: "missing",
          severity: "critical",
          title: "CSP not set",
          detail: "Add a Content-Security-Policy (or CSP report-only) that restricts script, object, base, and frame sources.",
        },
      ],
    };
  }

  const d = directivesFrom(String(raw));
  const issues: CspIssue[] = [];

  const defaultSrc = d.get("default-src") || [];
  const scriptSrc = d.get("script-src") || [];
  const styleSrc = d.get("style-src") || [];
  const objectSrc = d.get("object-src") || [];
  const frameAncestors = d.get("frame-ancestors") || [];
  const upgradeInsecure = d.has("upgrade-insecure-requests");

  if (defaultSrc.length === 0 && scriptSrc.length === 0) {
    issues.push({
      id: "no-default",
      severity: "high",
      title: "No default-src / script-src baseline",
      detail: "Without default-src or script-src, browsers fall back to permissive behavior for scripts in many cases.",
    });
  }

  const scriptBlob = scriptSrc.join(" ").toLowerCase();
  const defaultBlob = defaultSrc.join(" ").toLowerCase();

  if (scriptBlob.includes("'unsafe-inline'") || (defaultBlob.includes("'unsafe-inline'") && scriptSrc.length === 0)) {
    issues.push({
      id: "unsafe-inline-script",
      severity: "high",
      title: "unsafe-inline in script policy",
      detail: "Inline scripts bypass most CSP XSS protections. Prefer nonces or hashes, or strict script-src with external files only.",
    });
  }
  if (scriptBlob.includes("'unsafe-eval'") || defaultBlob.includes("'unsafe-eval'")) {
    issues.push({
      id: "unsafe-eval",
      severity: "high",
      title: "unsafe-eval allowed",
      detail: "eval(), new Function(), and similar are enabled — common XSS and gadget chain enablers.",
    });
  }
  if (scriptBlob.includes("*") || scriptBlob.includes("http:")) {
    issues.push({
      id: "broad-script",
      severity: "medium",
      title: "Broad or insecure script sources",
      detail: "Wildcard or http: script sources weaken CSP. Prefer https: origins and explicit host lists.",
    });
  }
  if (scriptBlob.includes("data:")) {
    issues.push({
      id: "data-script",
      severity: "medium",
      title: "data: in script-src",
      detail: "data: URIs for scripts can be abused in some chains; avoid unless required.",
    });
  }

  const styleBlob = styleSrc.join(" ").toLowerCase();
  if (styleBlob.includes("'unsafe-inline'")) {
    issues.push({
      id: "unsafe-inline-style",
      severity: "low",
      title: "unsafe-inline in style-src",
      detail: "Allows inline styles — lower risk than script but can aid UI redressing / some gadgets.",
    });
  }

  if (objectSrc.length === 0 && defaultSrc.length === 0) {
    issues.push({
      id: "object-src",
      severity: "medium",
      title: "object-src not restricted",
      detail: "Set object-src 'none' unless you embed plugins.",
    });
  } else {
    const ob = objectSrc.join(" ").toLowerCase();
    if (!ob.includes("'none'") && objectSrc.length > 0 && ob.includes("*")) {
      issues.push({
        id: "object-wide",
        severity: "medium",
        title: "Permissive object-src",
        detail: "Tighten object-src to 'none' if plugins are not needed.",
      });
    }
  }

  const fa = frameAncestors.join(" ").toLowerCase();
  if (frameAncestors.length === 0) {
    issues.push({
      id: "no-frame-ancestors",
      severity: "low",
      title: "frame-ancestors not set",
      detail: "Without frame-ancestors, clickjacking depends on X-Frame-Options only. Consider frame-ancestors 'self' or an explicit allowlist.",
    });
  } else if (fa.includes("*")) {
    issues.push({
      id: "frame-ancestors-star",
      severity: "medium",
      title: "frame-ancestors allows any parent",
      detail: "Wildcard frame-ancestors defeats clickjacking protection.",
    });
  }

  if (!upgradeInsecure) {
    issues.push({
      id: "no-upgrade",
      severity: "info",
      title: "upgrade-insecure-requests absent",
      detail: "Optional: add upgrade-insecure-requests to reduce mixed-content risk on HTTPS sites.",
    });
  }

  const critical = issues.filter((i) => i.severity === "critical").length;
  const high = issues.filter((i) => i.severity === "high").length;
  let score = 100 - critical * 25 - high * 12 - issues.filter((i) => i.severity === "medium").length * 6;
  score -= issues.filter((i) => i.severity === "low").length * 3;
  score -= issues.filter((i) => i.severity === "info").length * 1;
  score = Math.max(0, Math.min(100, Math.round(score)));

  const summary =
    issues.length === 0
      ? "Policy looks reasonably strict for automated checks — still verify in browser devtools."
      : `${issues.length} configuration note(s). Address high/critical items first.`;

  return { present: true, score, summary, issues };
}
