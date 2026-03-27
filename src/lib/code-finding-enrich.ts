import type { CodeFinding, CodeReviewResult } from "@/lib/types";

function defaultImpact(severity: CodeFinding["severity"], category: string): string {
  const sev =
    severity === "critical"
      ? "If real attackers can reach this code path with malicious input, they may steal data, run arbitrary code, or take over accounts."
      : severity === "high"
        ? "Serious weakness: often enables command execution, injection, or credential theft when combined with user-controlled data."
        : severity === "medium"
          ? "Weakens security posture; can make other bugs easier to exploit or cause reliability issues."
          : severity === "low"
            ? "Limited direct exploit value but worth fixing for hygiene and future-proofing."
            : "Low priority; mainly for awareness.";
  return `${sev} (Area: ${category}.)`;
}

/**
 * Adds plain-English vulnerability / impact / recommendation for UI and PDF reports.
 */
export function enrichFinding(f: CodeFinding): CodeFinding {
  const vulnerability =
    f.vulnerability ?? `${f.title} - ${f.description}`;
  const impact = f.impact ?? defaultImpact(f.severity, f.category);
  const recommendation =
    f.recommendation ??
    f.fix ??
    "Review whether untrusted input can reach this code; then apply secure libraries, parameterization, and least privilege.";
  return { ...f, vulnerability, impact, recommendation };
}

export function enrichReviewResult(r: CodeReviewResult): CodeReviewResult {
  return {
    ...r,
    findings: r.findings.map(enrichFinding),
  };
}
