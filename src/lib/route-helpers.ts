import { NextRequest, NextResponse } from "next/server";
import { guardArgusRequest } from "@/lib/api-guard";
import { argusAudit } from "@/lib/argus-audit";
import { parseScanTargetOrError, type ParsedScanTarget } from "@/lib/scan-target-policy";

export function guardScanPost(req: NextRequest): NextResponse | null {
  const g = guardArgusRequest(req);
  if (g) return g;
  return null;
}

export function auditRoute(req: NextRequest, event: string, meta: Record<string, unknown> = {}): void {
  argusAudit(event, { path: req.nextUrl.pathname, ...meta });
}

/** Guard + parse `url` from JSON body field. */
export async function readUrlBodyAndGuard(
  req: NextRequest,
): Promise<{ target: ParsedScanTarget } | NextResponse> {
  const denied = guardScanPost(req);
  if (denied) return denied;

  let body: { url?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const inputUrl = body?.url;
  if (typeof inputUrl !== "string" || !inputUrl.trim()) {
    return NextResponse.json({ error: "URL is required" }, { status: 400 });
  }

  const parsed = parseScanTargetOrError(inputUrl);
  if (parsed instanceof NextResponse) return parsed;
  auditRoute(req, "scan_target", { hostname: parsed.hostname });
  return { target: parsed };
}
