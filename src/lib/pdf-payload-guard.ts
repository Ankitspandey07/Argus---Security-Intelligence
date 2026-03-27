import { NextResponse } from "next/server";
import type { CodeReviewResult } from "@/lib/types";

const MAX_BODY_CHARS = 2_500_000;

export async function readJsonBodyLimited(req: Request): Promise<unknown | NextResponse> {
  const cl = req.headers.get("content-length");
  if (cl) {
    const n = parseInt(cl, 10);
    if (Number.isFinite(n) && n > MAX_BODY_CHARS) {
      return NextResponse.json({ error: `Request body too large (max ${MAX_BODY_CHARS} bytes)` }, { status: 413 });
    }
  }
  const text = await req.text();
  if (text.length > MAX_BODY_CHARS) {
    return NextResponse.json({ error: `Request body too large (max ${MAX_BODY_CHARS} chars)` }, { status: 413 });
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

type DepthOpts = { maxDepth?: number; maxArray?: number; maxKeys?: number; maxString?: number };

/** Strip obviously oversized strings from nested objects (shallow walk). */
function depthCheck(obj: unknown, depth = 0, opts: DepthOpts = {}): boolean {
  const maxDepth = opts.maxDepth ?? 12;
  const maxArray = opts.maxArray ?? 500;
  const maxKeys = opts.maxKeys ?? 400;
  const maxString = opts.maxString ?? 50_000;
  if (depth > maxDepth) return false;
  if (typeof obj === "string") return obj.length <= maxString;
  if (Array.isArray(obj)) {
    if (obj.length > maxArray) return false;
    return obj.every((x) => depthCheck(x, depth + 1, opts));
  }
  if (isPlainObject(obj)) {
    const keys = Object.keys(obj);
    if (keys.length > maxKeys) return false;
    for (const k of keys) {
      if (!depthCheck(obj[k], depth + 1, opts)) return false;
    }
    return true;
  }
  return true;
}

/** Minimal structural validation for security report PDF input (forgery / DoS mitigation). */
export function validateSecurityPdfPayload(body: unknown): NextResponse | Record<string, unknown> {
  if (!isPlainObject(body)) {
    return NextResponse.json({ error: "Body must be a JSON object" }, { status: 400 });
  }
  const scan = body.scan;
  if (!isPlainObject(scan)) {
    return NextResponse.json({ error: "scan object required" }, { status: 400 });
  }
  const target = scan.target;
  if (!isPlainObject(target) || typeof target.hostname !== "string" || target.hostname.length > 253) {
    return NextResponse.json({ error: "scan.target.hostname required" }, { status: 400 });
  }
  if (typeof scan.score !== "number" || typeof scan.grade !== "string") {
    return NextResponse.json({ error: "scan.score and scan.grade required" }, { status: 400 });
  }
  if (!Array.isArray(scan.headers)) {
    return NextResponse.json({ error: "scan.headers must be an array" }, { status: 400 });
  }
  if (scan.headers.length > 80) {
    return NextResponse.json({ error: "Too many header rows" }, { status: 400 });
  }
  if (!depthCheck(body, 0, { maxArray: 4000, maxKeys: 500, maxDepth: 14 })) {
    return NextResponse.json({ error: "Payload too deep or strings too long" }, { status: 400 });
  }
  return body;
}

export function validateCodeReviewPdfPayload(body: unknown): NextResponse | CodeReviewResult {
  if (!isPlainObject(body)) {
    return NextResponse.json({ error: "Body must be a JSON object" }, { status: 400 });
  }
  const raw = body.result;
  if (!isPlainObject(raw) || !Array.isArray(raw.findings)) {
    return NextResponse.json({ error: "result.findings array required" }, { status: 400 });
  }
  if (raw.findings.length > 300) {
    return NextResponse.json({ error: "Too many findings" }, { status: 400 });
  }
  if (!depthCheck(body)) {
    return NextResponse.json({ error: "Payload too large" }, { status: 400 });
  }
  return raw as unknown as CodeReviewResult;
}
