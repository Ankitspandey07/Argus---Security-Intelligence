import { NextRequest, NextResponse } from "next/server";
import dns from "dns/promises";
import { findFingerprintForCname } from "@/lib/takeover";
import { guardArgusRequest } from "@/lib/api-guard";
import { parseHostnameOrError } from "@/lib/scan-target-policy";
import { argusAudit } from "@/lib/argus-audit";
import { readJsonBody } from "@/lib/safe-request-json";

const UA = "Argus-TakeoverScan/1.0 (by Ankit Pandey)";
const DEFAULT_MAX_HOSTS = 40;
const ABS_MAX_HOSTS = 150;

async function resolveCname(host: string): Promise<string | null> {
  try {
    const r = await dns.resolveCname(host);
    return r[0] || null;
  } catch {
    return null;
  }
}

/** True if hostname has at least one A or AAAA (or CNAME chain root resolves). */
async function hostnameResolves(fqdn: string): Promise<boolean> {
  const h = fqdn.replace(/\.$/, "").toLowerCase();
  try {
    await dns.lookup(h, { verbatim: true });
    return true;
  } catch {
    try {
      const a = await dns.resolve4(h);
      return a.length > 0;
    } catch {
      try {
        const a6 = await dns.resolve6(h);
        return a6.length > 0;
      } catch {
        return false;
      }
    }
  }
}

type TakeoverSignal =
  | "likely_dangling"
  | "dns_dangling"
  | "possible"
  | "configured"
  | "error"
  | "no_cname";

export async function POST(req: NextRequest) {
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const parsed = await readJsonBody(req);
    if (!parsed.ok) return parsed.response;
    const { hosts, maxHosts: maxHostsRaw } = parsed.body as { hosts?: string[]; maxHosts?: number };
    if (!hosts?.length) return NextResponse.json({ error: "hosts array is required" }, { status: 400 });

    const cap = Math.min(
      Math.max(Number(maxHostsRaw) || DEFAULT_MAX_HOSTS, 1),
      ABS_MAX_HOSTS,
    );
    const unique = [...new Set(hosts.map((h) => h.toLowerCase().replace(/^https?:\/\//, "").split("/")[0]))].slice(
      0,
      cap,
    );

    for (const h of unique) {
      const chk = parseHostnameOrError(h);
      if (chk instanceof NextResponse) {
        return NextResponse.json({ error: `Host not allowed for takeover scan: ${h}` }, { status: 403 });
      }
    }
    argusAudit("takeover_scan", { count: unique.length });

    const results: {
      host: string;
      cname: string | null;
      service: string | null;
      httpStatus: number;
      signal: TakeoverSignal;
      detail: string;
    }[] = [];

    const throttleMs = unique.length > 25 ? 60 : 0;

    for (let i = 0; i < unique.length; i++) {
      const host = unique[i];
      if (throttleMs > 0 && i > 0) await new Promise((r) => setTimeout(r, throttleMs));
      const cname = await resolveCname(host);
      if (!cname) {
        results.push({
          host,
          cname: null,
          service: null,
          httpStatus: 0,
          signal: "no_cname",
          detail: "No CNAME (apex/AAAA only or no alias chain)",
        });
        continue;
      }

      const targetOk = await hostnameResolves(cname);
      if (!targetOk) {
        results.push({
          host,
          cname,
          service: null,
          httpStatus: 0,
          signal: "dns_dangling",
          detail: `CNAME → ${cname} — target does not resolve (NXDOMAIN / no records). High-confidence dangling DNS signal (Nuclei/subjack-style).`,
        });
        continue;
      }

      const fp = findFingerprintForCname(cname);
      if (!fp) {
        results.push({
          host,
          cname,
          service: null,
          httpStatus: 0,
          signal: "possible",
          detail: `CNAME → ${cname} (not in built-in SaaS fingerprint list — still verify ownership).`,
        });
        continue;
      }

      let httpStatus = 0;
      let body = "";
      try {
        const res = await fetch(`https://${host}/`, {
          redirect: "follow",
          signal: AbortSignal.timeout(8000),
          headers: { "User-Agent": UA, Accept: "text/html,application/xml,*/*" },
        });
        httpStatus = res.status;
        body = (await res.text()).slice(0, 12000);
      } catch {
        httpStatus = 0;
      }

      const matched = fp.unclaimedMarkers.some((re) => re.test(body));
      const signal: TakeoverSignal = matched ? "likely_dangling" : httpStatus === 0 ? "error" : "configured";
      const detail = matched
        ? `Response matches unclaimed pattern for ${fp.service} (fingerprint + body check).`
        : httpStatus === 0
          ? "HTTPS failed — manual review (internal-only or blocking)."
          : `HTTPS ${httpStatus} — ${fp.service} CNAME present; verify DNS is still claimed.`;

      results.push({
        host,
        cname,
        service: fp.service,
        httpStatus,
        signal,
        detail,
      });
    }

    const risky = results.filter((r) => r.signal === "likely_dangling" || r.signal === "dns_dangling");

    return NextResponse.json({
      scanned: results.length,
      hostsScanned: unique,
      maxHostsCap: cap,
      riskyCount: risky.length,
      risky,
      results,
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Takeover scan failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
