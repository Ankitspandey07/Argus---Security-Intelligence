import { NextRequest, NextResponse } from "next/server";
import { guardArgusRequest } from "@/lib/api-guard";
import { readJsonBody } from "@/lib/safe-request-json";
import { decodeJwtParts } from "@/lib/jwt-decode";

export interface AutoDetection {
  method: string;
  confidence: "high" | "medium" | "low";
  result: Record<string, unknown>;
}

function tryJwt(raw: string): AutoDetection | null {
  const t = raw.trim();
  if (!/^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(t)) return null;
  const dec = decodeJwtParts(t);
  if (!dec) return null;
  return {
    method: "JWT (JSON Web Token)",
    confidence: "high",
    result: {
      note: "Decoded without signature verification — not proof of authenticity.",
      header: dec.header,
      payload: dec.payload,
      signatureB64Url: dec.signature,
    },
  };
}

function tryHex(raw: string): AutoDetection | null {
  const clean = raw.replace(/\s/g, "");
  if (clean.length < 4 || clean.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]+$/.test(clean)) return null;
  try {
    const buf = Buffer.from(clean, "hex");
    const utf8 = buf.toString("utf8");
    const printable = /^[\x20-\x7E\n\r\t]+$/.test(utf8);
    return {
      method: "Hexadecimal → bytes",
      confidence: clean.length >= 8 ? "high" : "medium",
      result: {
        bytes: buf.length,
        utf8: printable ? utf8 : undefined,
        base64: buf.toString("base64"),
      },
    };
  } catch {
    return null;
  }
}

function tryBase64(raw: string): AutoDetection | null {
  const t = raw.trim().replace(/\s/g, "");
  if (t.length < 4) return null;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(t)) return null;
  try {
    const norm = t.replace(/-/g, "+").replace(/_/g, "/");
    const pad = (4 - (norm.length % 4)) % 4;
    const padded = norm + "=".repeat(pad);
    const buf = Buffer.from(padded, "base64");
    if (buf.length === 0) return null;
    const utf8 = buf.toString("utf8");
    const printable = /^[\x20-\x7E\n\r\t]+$/.test(utf8);
    return {
      method: "Base64",
      confidence: "medium",
      result: {
        bytes: buf.length,
        utf8: printable ? utf8 : undefined,
        hexPreview: buf.subarray(0, 32).toString("hex") + (buf.length > 32 ? "…" : ""),
      },
    };
  } catch {
    return null;
  }
}

function tryUrlEncoded(raw: string): AutoDetection | null {
  const t = raw.trim();
  if (!/%[0-9a-fA-F]{2}/.test(t)) return null;
  try {
    const once = decodeURIComponent(t);
    if (once === t) return null;
    return {
      method: "URL-encoded string",
      confidence: "high",
      result: { decoded: once },
    };
  } catch {
    return null;
  }
}

/** POST { raw: string } — CyberChef-style auto pipeline (best-effort). */
export async function POST(req: NextRequest) {
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const parsed = await readJsonBody(req);
    if (!parsed.ok) return parsed.response;
    const { raw } = parsed.body as { raw?: unknown };
    if (!raw || typeof raw !== "string") {
      return NextResponse.json({ error: "raw string required" }, { status: 400 });
    }

    const detections: AutoDetection[] = [];
    const seen = new Set<string>();

    const push = (d: AutoDetection | null) => {
      if (!d) return;
      const key = JSON.stringify(d.method + JSON.stringify(d.result).slice(0, 200));
      if (seen.has(key)) return;
      seen.add(key);
      detections.push(d);
    };

    const clean = raw.replace(/\s/g, "");
    const looksLikeHex = /^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0 && clean.length >= 4;

    push(tryJwt(raw));
    push(tryUrlEncoded(raw));
    push(tryHex(raw));
    if (!looksLikeHex) push(tryBase64(raw));

    if (detections.length === 0) {
      return NextResponse.json({
        detections: [],
        message: "No automatic decode matched. Try manual JWT / Base64 / Hex tabs.",
      });
    }

    return NextResponse.json({
      detections,
      hint: "Auto tries: JWT → URL decode → Hex → Base64. Multiple hits can all be valid layers.",
    });
  } catch (e: unknown) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "auto decode failed" }, { status: 500 });
  }
}
