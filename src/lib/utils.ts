export function normalizeTarget(input: string): { url: string; hostname: string } {
  let url = input.trim();
  if (!url.match(/^https?:\/\//i)) {
    url = `https://${url}`;
  }
  try {
    const parsed = new URL(url);
    return { url: parsed.origin, hostname: parsed.hostname };
  } catch {
    return { url: `https://${input}`, hostname: input };
  }
}

export function gradeFromScore(score: number): string {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 45) return "D";
  return "F";
}

export function gradeColor(grade: string): string {
  if (grade.startsWith("A")) return "#22c55e";
  if (grade === "B") return "#3b82f6";
  if (grade === "C") return "#f59e0b";
  if (grade === "D") return "#f97316";
  return "#ef4444";
}

export function severityColor(severity: string): string {
  switch (severity) {
    case "critical": return "#dc2626";
    case "high": return "#ef4444";
    case "medium": return "#f59e0b";
    case "low": return "#3b82f6";
    case "info": return "#6b7280";
    default: return "#6b7280";
  }
}
