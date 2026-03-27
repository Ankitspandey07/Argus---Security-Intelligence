import type { CodeFinding } from "@/lib/types";

function lineFromOffset(code: string, byteOrCharIndex: number): number {
  return code.slice(0, byteOrCharIndex).split("\n").length;
}

function pickSnippetFilename(code: string): string {
  if (/^\s*(?:from\s+[\w.]+\s+)?import\s+[\w.]+/m.test(code) && /\bdef\s+\w+\s*\(/.test(code)) return "snippet.py";
  if (/^\s*package\s+\w+/m.test(code)) return "snippet.go";
  if (/<\?php/i.test(code)) return "snippet.php";
  if (/^\s*import\s+java\./m.test(code) || /\bpublic\s+class\s+\w+/m.test(code)) return "snippet.java";
  if (/\bfn\s+main\s*\(\s*\)\s*\{/.test(code)) return "snippet.rs";
  if (/\brequire\s*\(\s*['"]express['"]|express\.Router|router\.(get|post)\s*\(/i.test(code)) return "snippet.js";
  if (/^\s*import\s+/.test(code) && /\bexport\s+/.test(code)) return "snippet.ts";
  return "snippet.js";
}

function mapSemgrepSeverity(s: string | undefined): CodeFinding["severity"] {
  const u = (s || "").toUpperCase();
  if (u === "ERROR") return "high";
  if (u === "WARNING") return "medium";
  if (u === "INFO") return "low";
  return "medium";
}

/**
 * Optional Semgrep pass: set ARGUS_ENABLE_SEMGREP=1 and install Semgrep on the server.
 * Node built-ins are required only inside this function so Next/Turbopack does not trace the repo at build time.
 */
export function runSemgrepOnCode(code: string): CodeFinding[] {
  if (process.env.ARGUS_ENABLE_SEMGREP !== "1") return [];
  if (!code.trim()) return [];

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { spawnSync } = require("node:child_process") as typeof import("node:child_process");
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const fs = require("node:fs") as typeof import("node:fs");
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const os = require("node:os") as typeof import("node:os");
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const path = require("node:path") as typeof import("node:path");

  const semgrepBin = process.env.SEMGREP_PATH?.trim() || "semgrep";
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "argus-semgrep-"));
  try {
    const name = pickSnippetFilename(code);
    const filePath = path.join(dir, name);
    fs.writeFileSync(filePath, code, "utf8");

    const r = spawnSync(semgrepBin, ["scan", "--config", "auto", "--json", "--quiet", dir], {
      encoding: "utf8",
      timeout: Math.min(90_000, Math.max(15_000, parseInt(process.env.ARGUS_SEMGREP_TIMEOUT_MS || "45000", 10) || 45_000)),
      maxBuffer: 12 * 1024 * 1024,
      env: { ...process.env, SEMGREP_ENABLE_VERSION_CHECK: "0" },
    });

    if (r.error || r.status === null) return [];

    let parsed: { results?: unknown[] };
    try {
      parsed = JSON.parse(r.stdout || "{}") as { results?: unknown[] };
    } catch {
      return [];
    }

    const results = Array.isArray(parsed.results) ? parsed.results : [];
    const out: CodeFinding[] = [];

    for (const raw of results) {
      const o = raw as Record<string, unknown>;
      const checkId = typeof o.check_id === "string" ? o.check_id : "semgrep";
      const extra = (o.extra as Record<string, unknown>) || {};
      const message = typeof extra.message === "string" ? extra.message : checkId;
      const severity = mapSemgrepSeverity(typeof extra.severity === "string" ? extra.severity : undefined);
      const start = o.start as { line?: number; offset?: number } | undefined;
      let line: number | undefined = typeof start?.line === "number" ? start.line : undefined;
      if (line == null && typeof start?.offset === "number") {
        line = lineFromOffset(code, start.offset);
      }
      out.push({
        severity,
        title: checkId.split(".").slice(-2).join(".") || "Semgrep finding",
        description: message,
        line,
        category: "Semgrep",
        fix: "Confirm with local `semgrep scan --config auto` and fix per rule documentation.",
        source: "semgrep",
      });
    }

    return out.slice(0, 80);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}
