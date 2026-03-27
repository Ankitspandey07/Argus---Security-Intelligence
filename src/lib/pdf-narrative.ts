import { GoogleGenAI } from "@google/genai";
import { GEMINI_FLASH_MODEL } from "@/lib/gemini-model";

export interface PdfNarrative {
  tagline: string;
  executivePlain: string;
  readingGuide: string;
  headersIntro: string;
  sslIntro?: string;
  portsIntro?: string;
  secretsIntro?: string;
  librariesIntro?: string;
  vtIntro?: string;
  takeoverIntro?: string;
  closing: string;
}

/**
 * Plain-English blurbs for PDF readers (non-experts). Best-effort; returns null if no API key.
 */
export async function generatePdfNarrative(scanBundle: Record<string, unknown>): Promise<PdfNarrative | null> {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey) return null;

  try {
    const ai = new GoogleGenAI({ apiKey });
    const json = JSON.stringify(scanBundle).slice(0, 14_000);
    const prompt = `You are writing short, friendly explanations for a security PDF report aimed at managers and developers who are not penetration testers.

Use SIMPLE English (8th grade reading level). No jargon unless you explain it in one short phrase. Be calm and factual.

SCAN JSON (truncated):
${json}

Return ONLY valid JSON with these exact keys (use empty string "" if a section does not apply):
{
  "tagline": "one engaging subtitle line under the report title",
  "executivePlain": "3-5 sentences: what we checked, overall posture in plain words, what the reader should do next",
  "readingGuide": "2-3 sentences on how to read colored sections and scores",
  "headersIntro": "2-3 sentences explaining HTTP security headers in plain English before technical details",
  "sslIntro": "2-3 sentences about TLS/SSL findings or empty if none",
  "portsIntro": "2-3 sentences about exposed ports / Shodan or empty",
  "secretsIntro": "2-3 sentences about leaked patterns / secrets or empty",
  "librariesIntro": "2-4 sentences about JavaScript libraries and CVE checks or empty",
  "vtIntro": "2-4 sentences about VirusTotal reputation signals or empty",
  "takeoverIntro": "2-3 sentences about subdomain takeover heuristics or empty",
  "closing": "2 sentences thanking the reader and reminding them to verify fixes in staging/production"
}

Do not include markdown. Do not invent CVE numbers not implied by the JSON.`;

    const response = await ai.models.generateContent({
      model: GEMINI_FLASH_MODEL,
      contents: prompt,
      config: { responseMimeType: "application/json" },
    });

    const text = response.text || "{}";
    const parsed = JSON.parse(text) as PdfNarrative;
    if (!parsed.executivePlain || !parsed.tagline) return null;
    return parsed;
  } catch {
    return null;
  }
}
