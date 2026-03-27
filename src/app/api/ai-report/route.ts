import { NextRequest, NextResponse } from "next/server";
import { GoogleGenAI } from "@google/genai";
import type { AIReport } from "@/lib/types";
import { GEMINI_FLASH_MODEL } from "@/lib/gemini-model";
import { guardArgusRequest } from "@/lib/api-guard";
import { argusAudit } from "@/lib/argus-audit";
import { coerceAiReport } from "@/lib/ai-response-validate";
import { readJsonBody } from "@/lib/safe-request-json";

export async function POST(req: NextRequest) {
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const parsed = await readJsonBody(req);
    if (!parsed.ok) return parsed.response;
    const scanData = (parsed.body as { scanData?: unknown })?.scanData;
    if (!scanData) return NextResponse.json({ error: "Scan data is required" }, { status: 400 });
    const serialized = JSON.stringify(scanData);
    if (serialized.length > 100_000) {
      return NextResponse.json({ error: "scanData payload too large" }, { status: 413 });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return NextResponse.json({ error: "AI service not configured. Set GEMINI_API_KEY in environment." }, { status: 503 });

    const ai = new GoogleGenAI({ apiKey });

    const prompt = `You are a senior cybersecurity analyst. Analyze the following security scan results and produce a professional security assessment report.

SCAN DATA:
${JSON.stringify(scanData, null, 2).substring(0, 12000)}

Return a JSON object with this exact schema (no markdown, just JSON):
{
  "executiveSummary": "A professional 3-4 sentence executive summary suitable for management",
  "riskLevel": "Critical|High|Medium|Low|Minimal",
  "topFindings": ["most critical finding 1", "finding 2", "finding 3", "finding 4", "finding 5"],
  "recommendations": ["prioritized actionable recommendation 1", "recommendation 2", ...],
  "complianceNotes": ["relevant compliance note about OWASP/PCI-DSS/GDPR/HIPAA if applicable", ...]
}`;

    const response = await ai.models.generateContent({
      model: GEMINI_FLASH_MODEL,
      contents: prompt,
      config: { responseMimeType: "application/json" },
    });

    const text = response.text || "{}";
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      return NextResponse.json({ error: "AI returned invalid JSON" }, { status: 502 });
    }
    const result = coerceAiReport(raw);
    if (!result) {
      return NextResponse.json({ error: "AI response failed schema checks" }, { status: 502 });
    }
    argusAudit("ai_report", { target: typeof scanData === "object" && scanData && "target" in scanData ? String((scanData as { target?: unknown }).target) : "unknown" });
    return NextResponse.json(result);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "AI report generation failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
