import { NextRequest, NextResponse } from "next/server";
import { readUrlBodyAndGuard } from "@/lib/route-helpers";
import type { FetchedMeta, SiteMetaResult } from "@/lib/mail-site-types";
import { PRIMARY_SCAN_FETCH_HEADERS } from "@/lib/scanner-fetch-headers";

export const runtime = "nodejs";

async function fetchText(origin: string, path: string): Promise<FetchedMeta | { skipped: true; reason: string }> {
  const url = `${origin.replace(/\/$/, "")}${path}`;
  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: AbortSignal.timeout(10_000),
      headers: {
        ...PRIMARY_SCAN_FETCH_HEADERS,
        Accept: "text/plain,text/html,application/xhtml+xml,*/*;q=0.5",
      },
    });
    const text = await res.text();
    return {
      path,
      finalUrl: res.url,
      status: res.status,
      contentType: res.headers.get("content-type"),
      accessControlAllowOrigin: res.headers.get("access-control-allow-origin"),
      excerpt: text.slice(0, 2500),
      bytes: text.length,
    };
  } catch (e: unknown) {
    return {
      skipped: true,
      reason: e instanceof Error ? e.message : "fetch failed",
    };
  }
}

export async function POST(req: NextRequest) {
  try {
    const parsed = await readUrlBodyAndGuard(req);
    if (parsed instanceof NextResponse) return parsed;
    const { url } = parsed.target;
    let origin: string;
    try {
      origin = new URL(url).origin;
    } catch {
      return NextResponse.json({ error: "Invalid target URL" }, { status: 400 });
    }

    const [robots, securityTxt] = await Promise.all([
      fetchText(origin, "/robots.txt"),
      fetchText(origin, "/.well-known/security.txt"),
    ]);

    const result: SiteMetaResult = { origin, robots, securityTxt };
    return NextResponse.json(result);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Site meta fetch failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
