import { NextRequest, NextResponse } from "next/server";
import dns from "dns/promises";
import { readUrlBodyAndGuard } from "@/lib/route-helpers";
import type { MailAuthResult } from "@/lib/mail-site-types";

export const runtime = "nodejs";

function apexCandidates(hostname: string): string[] {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  const out = [h];
  if (h.startsWith("www.") && h.length > 4) out.push(h.slice(4));
  return [...new Set(out)];
}

export async function POST(req: NextRequest) {
  try {
    const parsed = await readUrlBodyAndGuard(req);
    if (parsed instanceof NextResponse) return parsed;
    const { hostname } = parsed.target;
    const checked = apexCandidates(hostname);
    const notes: string[] = [];

    let mx: { exchange: string; priority: number }[] = [];
    try {
      mx = await dns.resolveMx(hostname);
      mx.sort((a, b) => a.priority - b.priority);
    } catch {
      notes.push("No MX records (or lookup failed) — mail may use a parent domain or third-party MX.");
    }

    let spf: { host: string; record: string } | null = null;
    for (const host of checked) {
      try {
        const chunks = await dns.resolveTxt(host);
        const flat = chunks.map((c) => c.join(""));
        const hit = flat.find((t) => /^v=spf1\b/i.test(t));
        if (hit) {
          spf = { host, record: hit };
          break;
        }
      } catch {
        /* no TXT */
      }
    }

    let dmarc: { host: string; record: string } | null = null;
    for (const host of checked) {
      const dmarcHost = `_dmarc.${host}`;
      try {
        const chunks = await dns.resolveTxt(dmarcHost);
        const flat = chunks.map((c) => c.join(""));
        const hit = flat.find((t) => /^v=DMARC1\b/i.test(t));
        if (hit) {
          dmarc = { host: dmarcHost, record: hit };
          break;
        }
      } catch {
        /* none */
      }
    }

    if (!dmarc) notes.push("No DMARC record found on checked hosts — consider p=none→quarantine→reject rollout.");

    const result: MailAuthResult = {
      hostname,
      checkedHosts: checked,
      mx,
      spf,
      dmarc,
      notes,
    };
    return NextResponse.json(result);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Mail auth lookup failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
