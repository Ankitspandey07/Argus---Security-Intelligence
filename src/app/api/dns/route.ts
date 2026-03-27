import { NextRequest, NextResponse } from "next/server";
import { readUrlBodyAndGuard } from "@/lib/route-helpers";
import dns from "dns/promises";
import type { DNSResult, DNSRecord } from "@/lib/types";

export async function POST(req: NextRequest) {
  try {
    const parsed = await readUrlBodyAndGuard(req);
    if (parsed instanceof NextResponse) return parsed;
    const { hostname } = parsed.target;
    const records: DNSRecord[] = [];

    const lookups = [
      { type: "A", fn: () => dns.resolve4(hostname) },
      { type: "AAAA", fn: () => dns.resolve6(hostname) },
      { type: "CNAME", fn: () => dns.resolveCname(hostname) },
      { type: "MX", fn: () => dns.resolveMx(hostname) },
      { type: "NS", fn: () => dns.resolveNs(hostname) },
      { type: "TXT", fn: () => dns.resolveTxt(hostname) },
      { type: "SOA", fn: () => dns.resolveSoa(hostname) },
      { type: "SRV", fn: () => dns.resolveSrv(hostname) },
    ];

    const results = await Promise.allSettled(lookups.map(l => l.fn()));

    results.forEach((result, i) => {
      if (result.status !== "fulfilled") return;
      const type = lookups[i].type;
      const data = result.value;

      if (type === "A" || type === "AAAA" || type === "CNAME" || type === "NS") {
        (data as string[]).forEach(v => records.push({ type, value: v }));
      } else if (type === "MX") {
        (data as { exchange: string; priority: number }[]).forEach(v =>
          records.push({ type, value: v.exchange, priority: v.priority })
        );
      } else if (type === "TXT") {
        (data as string[][]).forEach(v => records.push({ type, value: v.join("") }));
      } else if (type === "SOA") {
        const soa = data as { nsname: string; hostmaster: string; serial: number; minttl: number };
        records.push({ type, value: `${soa.nsname} ${soa.hostmaster} (serial: ${soa.serial})`, ttl: soa.minttl });
      } else if (type === "SRV") {
        (data as { name: string; port: number; priority: number; weight: number }[]).forEach(v =>
          records.push({ type, value: `${v.name}:${v.port}`, priority: v.priority })
        );
      }
    });

    let hasDNSSEC = false;
    try {
      const resolver = new dns.Resolver();
      resolver.setServers(["8.8.8.8"]);
      const txt = await resolver.resolveTxt(hostname);
      const nsec = records.some(r => r.type === "TXT" && /DNSSEC/i.test(r.value));
      hasDNSSEC = nsec;
    } catch { /* DNSSEC check optional */ }

    try {
      const dnskey = await dns.resolve(hostname, "DNSKEY" as never);
      if (dnskey) hasDNSSEC = true;
    } catch { /* expected to fail if no DNSSEC */ }

    const nameservers = records.filter(r => r.type === "NS").map(r => r.value);
    const mailServers = records.filter(r => r.type === "MX").map(r => r.value);

    const result: DNSResult = { records, hasDNSSEC, nameservers, mailServers };
    return NextResponse.json(result);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "DNS lookup failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
