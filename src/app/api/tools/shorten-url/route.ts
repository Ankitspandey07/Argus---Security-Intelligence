import { NextRequest, NextResponse } from "next/server";
import { isBlockedShortenHostname } from "@/lib/url-safety";
import { guardArgusRequest } from "@/lib/api-guard";
import { readJsonBody } from "@/lib/safe-request-json";

const MAX_URL_LEN = 2000;
const FETCH_MS = 12_000;

/**
 * Proxies public shortener APIs (no storage in Argus).
 * Blocks obvious private/metadata hosts to reduce SSRF-style abuse.
 */
export async function POST(req: NextRequest) {
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const parsed = await readJsonBody(req);
    if (!parsed.ok) return parsed.response;
    const raw = (parsed.body as { url?: unknown })?.url;
    if (typeof raw !== "string" || !raw.trim()) {
      return NextResponse.json({ error: "Provide a non-empty url string." }, { status: 400 });
    }
    const trimmed = raw.trim();
    if (trimmed.length > MAX_URL_LEN) {
      return NextResponse.json({ error: `URL too long (max ${MAX_URL_LEN} chars).` }, { status: 400 });
    }

    let u: URL;
    try {
      u = new URL(trimmed);
    } catch {
      return NextResponse.json({ error: "Invalid URL — include scheme, e.g. https://example.com/path" }, { status: 400 });
    }

    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return NextResponse.json({ error: "Only http: and https: URLs are allowed." }, { status: 400 });
    }

    if (isBlockedShortenHostname(u.hostname)) {
      return NextResponse.json(
        { error: "This hostname is not allowed (local/private/reserved ranges)." },
        { status: 400 },
      );
    }

    const target = u.href;
    const ac = new AbortController();
    const to = setTimeout(() => ac.abort(), FETCH_MS);

    const tryIsGd = async (): Promise<string | null> => {
      const r = await fetch(
        `https://is.gd/create.php?format=simple&url=${encodeURIComponent(target)}`,
        {
          method: "GET",
          headers: { Accept: "text/plain", "User-Agent": "Argus/1.0 (security lab)" },
          signal: ac.signal,
        },
      );
      const text = (await r.text()).trim();
      if (!r.ok || text.startsWith("Error:") || !/^https?:\/\//i.test(text)) return null;
      return text;
    };

    const tryTinyurl = async (): Promise<string | null> => {
      const r = await fetch(
        `https://tinyurl.com/api-create.php?url=${encodeURIComponent(target)}`,
        {
          method: "GET",
          headers: { Accept: "text/plain", "User-Agent": "Argus/1.0 (security lab)" },
          signal: ac.signal,
        },
      );
      const text = (await r.text()).trim();
      if (!r.ok || !/^https?:\/\//i.test(text)) return null;
      return text;
    };

    try {
      let short = await tryIsGd();
      if (!short) short = await tryTinyurl();
      if (!short) {
        return NextResponse.json(
          {
            error:
              "Shortener services returned no link (rate limit, blocklist, or network). Try again later or use an external shortener.",
          },
          { status: 502 },
        );
      }
      return NextResponse.json({
        type: "url_shorten",
        originalUrl: target,
        shortUrl: short,
        note: "Third-party shortener; link may expire or be logged. Never shorten secrets or auth URLs.",
      });
    } finally {
      clearTimeout(to);
    }
  } catch (e: unknown) {
    if (e instanceof Error && e.name === "AbortError") {
      return NextResponse.json({ error: "Shortener request timed out." }, { status: 504 });
    }
    const msg = e instanceof Error ? e.message : "Shorten failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
