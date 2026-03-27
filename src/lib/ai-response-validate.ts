import type { AIReport } from "@/lib/types";
import type { CodeReviewResult } from "@/lib/types";

const RISKS = new Set(["Critical", "High", "Medium", "Low", "Minimal"]);

function isStr(v: unknown, max: number): v is string {
  return typeof v === "string" && v.length <= max;
}

function isStrArr(v: unknown, maxLen: number, maxItem: number): v is string[] {
  return Array.isArray(v) && v.length <= maxLen && v.every((x) => typeof x === "string" && x.length <= maxItem);
}

/** Normalize Gemini AI report JSON — drops unknown fields, caps sizes. */
export function coerceAiReport(raw: unknown): AIReport | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  const riskLevel = o.riskLevel;
  const rs = typeof riskLevel === "string" ? riskLevel : "";
  const risk = RISKS.has(rs) ? rs : "Medium";

  const executiveSummary = isStr(o.executiveSummary, 8000) ? o.executiveSummary : "No summary returned.";
  const topFindings = isStrArr(o.topFindings, 25, 2000) ? o.topFindings : [];
  const recommendations = isStrArr(o.recommendations, 40, 2000) ? o.recommendations : [];
  const complianceNotes = isStrArr(o.complianceNotes, 30, 2000) ? o.complianceNotes : [];

  return {
    executiveSummary,
    riskLevel: risk,
    topFindings: topFindings.length ? topFindings : ["(No structured findings returned)"],
    recommendations: recommendations.length ? recommendations : ["Review raw scan results in the dashboard."],
    complianceNotes,
  };
}

const SEV = new Set(["critical", "high", "medium", "low", "info"]);

export function coerceCodeReviewResult(raw: unknown): CodeReviewResult | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;

  const overallRisk = typeof o.overallRisk === "string" && ["critical", "high", "medium", "low", "safe"].includes(o.overallRisk)
    ? (o.overallRisk as CodeReviewResult["overallRisk"])
    : "medium";

  const score = typeof o.score === "number" && Number.isFinite(o.score) ? Math.max(0, Math.min(100, Math.round(o.score))) : 50;

  const findingsIn = Array.isArray(o.findings) ? o.findings : [];
  const findings = findingsIn.slice(0, 200).map((f) => {
    const x = f && typeof f === "object" && !Array.isArray(f) ? (f as Record<string, unknown>) : {};
    const sev = typeof x.severity === "string" && SEV.has(x.severity) ? x.severity : "info";
    return {
      severity: sev as "critical" | "high" | "medium" | "low" | "info",
      title: typeof x.title === "string" ? x.title.slice(0, 500) : "Finding",
      description: typeof x.description === "string" ? x.description.slice(0, 8000) : "",
      line: typeof x.line === "number" && Number.isFinite(x.line) ? Math.max(1, Math.floor(x.line)) : undefined,
      category: typeof x.category === "string" ? x.category.slice(0, 200) : "General",
      cwe: typeof x.cwe === "string" ? x.cwe.slice(0, 32) : undefined,
      fix: typeof x.fix === "string" ? x.fix.slice(0, 4000) : undefined,
      vulnerability: typeof x.vulnerability === "string" ? x.vulnerability.slice(0, 2000) : undefined,
      impact: typeof x.impact === "string" ? x.impact.slice(0, 4000) : undefined,
      recommendation: typeof x.recommendation === "string" ? x.recommendation.slice(0, 4000) : undefined,
      evidence: typeof x.evidence === "string" ? x.evidence.slice(0, 4000) : undefined,
      source: "ai" as const,
    };
  });

  const summary = typeof o.summary === "string" ? o.summary.slice(0, 8000) : "AI review completed.";
  const recsIn = Array.isArray(o.recommendations) ? o.recommendations : [];
  const recommendations = recsIn
    .filter((r): r is string => typeof r === "string")
    .map((r) => r.slice(0, 2000))
    .slice(0, 40);

  return {
    overallRisk,
    score,
    findings,
    summary,
    recommendations: recommendations.length ? recommendations : ["Review SAST findings and confirm data flow."],
    reviewSource: "gemini",
  };
}
