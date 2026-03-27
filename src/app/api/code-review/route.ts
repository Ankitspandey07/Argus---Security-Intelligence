import { NextRequest, NextResponse } from "next/server";
import { GoogleGenAI } from "@google/genai";
import type { CodeReviewResult } from "@/lib/types";
import { GEMINI_FLASH_MODEL } from "@/lib/gemini-model";
import { enrichReviewResult } from "@/lib/code-finding-enrich";
import { mergeSastWithAi, inferPrimaryLanguageForPrompt, runSastStaticScan } from "@/lib/sast-static-scan";
import { guardArgusRequest } from "@/lib/api-guard";
import { coerceCodeReviewResult } from "@/lib/ai-response-validate";
import { readJsonBody } from "@/lib/safe-request-json";

const MAX_CODE_CHARS = 600_000;

async function optionalSemgrepFindings(codeStr: string) {
  if (process.env.ARGUS_ENABLE_SEMGREP !== "1") return [];
  const { runSemgrepOnCode } = await import("@/lib/semgrep-code-review");
  return runSemgrepOnCode(codeStr);
}

function isGeminiQuotaLikeError(e: unknown): boolean {
  const msg =
    e instanceof Error ? e.message : typeof e === "string" ? e : JSON.stringify(e);
  if (/429|RESOURCE_EXHAUSTED|quota|Quota exceeded|rate limit|rate-limit/i.test(msg)) return true;
  if (typeof e === "object" && e !== null) {
    const o = e as Record<string, unknown>;
    if (o.status === 429 || o.code === 429) return true;
    const err = o.error as Record<string, unknown> | undefined;
    if (err && (err.code === 429 || err.status === "RESOURCE_EXHAUSTED")) return true;
  }
  return false;
}

const DEFAULT_AI_TIMEOUT_MS = 20_000;

function codeReviewAiTimeoutMs(): number {
  const raw = process.env.CODE_REVIEW_AI_TIMEOUT_MS;
  if (!raw) return DEFAULT_AI_TIMEOUT_MS;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n)) return DEFAULT_AI_TIMEOUT_MS;
  return Math.min(120_000, Math.max(8_000, n));
}

async function tryGeminiReview(
  ai: GoogleGenAI,
  codeStr: string,
  language: unknown,
  context: unknown,
  opts?: { abortSignal?: AbortSignal; httpTimeoutMs?: number; primaryLanguageHint?: string },
): Promise<CodeReviewResult> {
  const langHint =
    typeof opts?.primaryLanguageHint === "string" && opts.primaryLanguageHint.trim().length > 0
      ? `PRIMARY LANGUAGE (follow this; do not classify the whole snippet as SQL only because a string contains SELECT/INSERT): ${opts.primaryLanguageHint.trim()}`
      : !language || language === "Auto-detect"
        ? "First infer the most likely programming language from the code, then review it as that language."
        : `The code is intended to be ${language}.`;

  const prompt = `You are an expert application security engineer performing a code review.
${langHint}
${context ? `Context from the developer: ${context}` : ""}

CODE:
\`\`\`
${codeStr.substring(0, 15000)}
\`\`\`

Return a JSON object with this exact schema (no markdown, just JSON):
{
  "overallRisk": "critical|high|medium|low|safe",
  "score": <0-100 security score>,
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "short title",
      "description": "detailed explanation",
      "line": <line number or null>,
      "category": "OWASP category or type (e.g. Injection, XSS, Auth, Crypto, Config)",
      "cwe": "CWE-XXX if applicable",
      "fix": "specific code fix suggestion",
      "vulnerability": "one sentence: what in the code is unsafe",
      "impact": "one or two sentences: what an attacker or failure mode could cause",
      "recommendation": "one sentence: what the developer should do next"
    }
  ],
  "summary": "2-3 sentence summary",
  "recommendations": ["actionable recommendation 1", "recommendation 2", ...]
}`;

  const httpTimeoutMs = opts?.httpTimeoutMs ?? DEFAULT_AI_TIMEOUT_MS;
  const response = await ai.models.generateContent({
    model: GEMINI_FLASH_MODEL,
    contents: prompt,
    config: {
      responseMimeType: "application/json",
      maxOutputTokens: 8192,
      abortSignal: opts?.abortSignal,
      httpOptions: {
        timeout: httpTimeoutMs,
        /** Default is multiple retries; each can add another full timeout window. */
        retryOptions: { attempts: 1 },
      },
    },
  });

  const text = response.text || "{}";
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error("Gemini returned non-JSON");
  }
  const coerced = coerceCodeReviewResult(raw);
  if (!coerced) throw new Error("Gemini returned unusable JSON shape");
  const findings = (coerced.findings || []).map((f) => ({ ...f, source: "ai" as const }));
  return {
    ...coerced,
    findings,
    reviewSource: "gemini",
  };
}

export async function POST(req: NextRequest) {
  let codeStr = "";
  let reviewLanguage: unknown;
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const parsed = await readJsonBody(req);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body as { code?: unknown; language?: unknown; context?: unknown };
    const { code, language, context } = body;
    reviewLanguage = language;
    codeStr = typeof code === "string" ? code : "";
    if (!codeStr) return NextResponse.json({ error: "Code is required" }, { status: 400 });
    if (codeStr.length > MAX_CODE_CHARS) {
      return NextResponse.json({ error: `Code too large (max ${MAX_CODE_CHARS} characters)` }, { status: 413 });
    }

    const semgrepFindings = await optionalSemgrepFindings(codeStr);
    const sast = runSastStaticScan(codeStr, reviewLanguage, semgrepFindings);

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return NextResponse.json(
        enrichReviewResult({
          ...sast,
          staticFindingsCount: sast.findings.length,
          aiFindingsCount: 0,
        }),
      );
    }

    const ai = new GoogleGenAI({ apiKey });
    const aiTimeoutMs = codeReviewAiTimeoutMs();
    const aiAbort = new AbortController();
    const aiDeadline = setTimeout(() => aiAbort.abort(), aiTimeoutMs);

    try {
      const gemini = await tryGeminiReview(ai, codeStr, reviewLanguage, context, {
        abortSignal: aiAbort.signal,
        httpTimeoutMs: aiTimeoutMs,
        primaryLanguageHint: inferPrimaryLanguageForPrompt(codeStr, reviewLanguage),
      });
      clearTimeout(aiDeadline);
      const merged = mergeSastWithAi(sast, gemini);
      return NextResponse.json(enrichReviewResult(merged));
    } catch (e: unknown) {
      clearTimeout(aiDeadline);
      if (aiAbort.signal.aborted) {
        return NextResponse.json(
          enrichReviewResult({
            ...sast,
            staticFindingsCount: sast.findings.length,
            aiFindingsCount: 0,
            providerNote: `AI pass timed out after ~${Math.round(aiTimeoutMs / 1000)}s - static (SAST-style) scan is shown below. Increase CODE_REVIEW_AI_TIMEOUT_MS if you need longer.`,
          }),
        );
      }
      if (isGeminiQuotaLikeError(e)) {
        return NextResponse.json(
          enrichReviewResult({
            ...sast,
            staticFindingsCount: sast.findings.length,
            aiFindingsCount: 0,
            providerNote:
              "Gemini quota or rate limit - static (SAST-style) scan completed. Retry AI later or check billing.",
          }),
        );
      }
      const msg = e instanceof Error ? e.message : "Code review failed";
      if (msg.length > 280 && /generativelanguage|google\.api/i.test(msg)) {
        return NextResponse.json(
          enrichReviewResult({
            ...sast,
            staticFindingsCount: sast.findings.length,
            aiFindingsCount: 0,
            providerNote: "AI service error - static (SAST-style) scan is shown below.",
          }),
        );
      }
      return NextResponse.json(
        enrichReviewResult({
          ...sast,
          staticFindingsCount: sast.findings.length,
          aiFindingsCount: 0,
          providerNote: "AI pass failed - static (SAST-style) scan is shown below.",
        }),
      );
    }
  } catch (e: unknown) {
    if (codeStr) {
      const semgrepFindings = await optionalSemgrepFindings(codeStr);
      const sast = runSastStaticScan(codeStr, reviewLanguage, semgrepFindings);
      return NextResponse.json(
        enrichReviewResult({
          ...sast,
          staticFindingsCount: sast.findings.length,
          aiFindingsCount: 0,
          providerNote: "Request handling error - static scan only.",
        }),
      );
    }
    return NextResponse.json({ error: "Review temporarily unavailable." }, { status: 503 });
  }
}
