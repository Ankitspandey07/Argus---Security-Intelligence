import { NextRequest, NextResponse } from "next/server";
import { readUrlBodyAndGuard } from "@/lib/route-helpers";
import type { SubdomainResult } from "@/lib/types";

export async function POST(req: NextRequest) {
  try {
    const parsed = await readUrlBodyAndGuard(req);
    if (parsed instanceof NextResponse) return parsed;
    const { hostname } = parsed.target;
    const baseDomain = hostname.replace(/^www\./, "");

    const subdomains = new Map<string, SubdomainResult>();

    // crt.sh — Certificate Transparency logs (real, free, no key)
    try {
      const crtRes = await fetch(
        `https://crt.sh/?q=%25.${encodeURIComponent(baseDomain)}&output=json`,
        { signal: AbortSignal.timeout(20000) }
      );
      if (crtRes.ok) {
        const crtData = await crtRes.json() as { name_value: string; entry_timestamp?: string }[];
        for (const entry of crtData) {
          const names = entry.name_value.split("\n").map(n => n.trim().toLowerCase());
          for (const name of names) {
            if (name.endsWith(baseDomain) && !name.includes("*") && !subdomains.has(name)) {
              subdomains.set(name, {
                subdomain: name,
                source: "Certificate Transparency (crt.sh)",
                firstSeen: entry.entry_timestamp,
              });
            }
          }
        }
      }
    } catch { /* crt.sh may timeout on large domains */ }

    // HackerTarget API — Free DNS lookup (real, free, limited)
    try {
      const htRes = await fetch(
        `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(baseDomain)}`,
        { signal: AbortSignal.timeout(15000) }
      );
      if (htRes.ok) {
        const text = await htRes.text();
        if (!text.includes("error") && !text.includes("API count exceeded")) {
          const lines = text.trim().split("\n");
          for (const line of lines) {
            const [sub] = line.split(",");
            if (sub && sub.endsWith(baseDomain) && !subdomains.has(sub.toLowerCase())) {
              subdomains.set(sub.toLowerCase(), {
                subdomain: sub.toLowerCase(),
                source: "HackerTarget DNS Search",
              });
            }
          }
        }
      }
    } catch { /* HackerTarget optional */ }

    const results = Array.from(subdomains.values())
      .sort((a, b) => a.subdomain.localeCompare(b.subdomain));

    return NextResponse.json({ domain: baseDomain, count: results.length, subdomains: results });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Subdomain discovery failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
