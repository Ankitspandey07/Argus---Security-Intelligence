import { timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

function clientIp(req: NextRequest): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    const first = xff.split(",")[0]?.trim();
    if (first) return first;
  }
  const real = req.headers.get("x-real-ip")?.trim();
  if (real) return real;
  return "unknown";
}

type Bucket = { count: number; resetAt: number };
const rateBuckets = new Map<string, Bucket>();
const MAX_BUCKETS = 8000;

function pruneBuckets(now: number): void {
  if (rateBuckets.size <= MAX_BUCKETS) return;
  for (const [k, v] of rateBuckets) {
    if (now > v.resetAt) rateBuckets.delete(k);
  }
}

/**
 * Optional shared API key. If ARGUS_API_KEY is set, require:
 * Authorization: Bearer <key> OR header x-argus-key: <key>
 */
export function verifyArgusApiKey(req: NextRequest): NextResponse | null {
  const expected = process.env.ARGUS_API_KEY?.trim();
  if (!expected) return null;

  const auth = req.headers.get("authorization");
  const xh = req.headers.get("x-argus-key");
  const token =
    auth?.startsWith("Bearer ") ? auth.slice(7).trim() : xh?.trim() ?? "";

  const match =
    token.length === expected.length &&
    (() => {
      try {
        return timingSafeEqual(Buffer.from(token, "utf8"), Buffer.from(expected, "utf8"));
      } catch {
        return false;
      }
    })();

  if (!match) {
    return NextResponse.json(
      {
        error:
          "Unauthorized. Send header Authorization: Bearer <ARGUS_API_KEY> or x-argus-key (same value as server env).",
      },
      { status: 401 },
    );
  }
  return null;
}

/**
 * Simple sliding-window rate limit per client IP.
 * ARGUS_RATE_LIMIT_WINDOW_MS (default 60000), ARGUS_RATE_LIMIT_MAX (default 45) requests per window.
 */
export function checkArgusRateLimit(req: NextRequest): NextResponse | null {
  const windowMs = Math.min(
    600_000,
    Math.max(5_000, parseInt(process.env.ARGUS_RATE_LIMIT_WINDOW_MS || "60000", 10) || 60_000),
  );
  const maxReq = Math.min(
    500,
    Math.max(5, parseInt(process.env.ARGUS_RATE_LIMIT_MAX || "45", 10) || 45),
  );

  const ip = clientIp(req);
  const now = Date.now();
  pruneBuckets(now);

  let b = rateBuckets.get(ip);
  if (!b || now > b.resetAt) {
    b = { count: 0, resetAt: now + windowMs };
    rateBuckets.set(ip, b);
  }
  b.count += 1;
  if (b.count > maxReq) {
    return NextResponse.json(
      {
        error: `Rate limit exceeded (${maxReq} requests per ${windowMs}ms per client). Try again later.`,
      },
      { status: 429 },
    );
  }
  return null;
}

/** First-line guard for most /api routes. */
export function guardArgusRequest(req: NextRequest): NextResponse | null {
  const keyErr = verifyArgusApiKey(req);
  if (keyErr) return keyErr;
  return checkArgusRateLimit(req);
}

export { clientIp as getArgusClientIp };
