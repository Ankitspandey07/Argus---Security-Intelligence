import { NextRequest, NextResponse } from "next/server";
import { readUrlBodyAndGuard } from "@/lib/route-helpers";
import dns from "dns/promises";
import type { PortScanResult } from "@/lib/types";
import { CRITICAL_EXPOSED_PORTS } from "@/lib/dangerous-ports";

export async function POST(req: NextRequest) {
  try {
    const parsed = await readUrlBodyAndGuard(req);
    if (parsed instanceof NextResponse) return parsed;
    const { hostname } = parsed.target;

    let ip: string;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      ip = hostname;
    } else {
      try {
        const addrs = await dns.resolve4(hostname);
        ip = addrs[0] || hostname;
      } catch {
        return NextResponse.json({ error: "Could not resolve hostname to IP" }, { status: 400 });
      }
    }

    // Shodan InternetDB — free, no API key needed
    const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`, {
      signal: AbortSignal.timeout(10000),
    });

    if (!shodanRes.ok) {
      if (shodanRes.status === 404) {
        return NextResponse.json({
          ip,
          ports: [],
          hostnames: [hostname],
          totalVulns: 0,
          message: "No data found for this IP in Shodan InternetDB",
        });
      }
      throw new Error(`Shodan returned ${shodanRes.status}`);
    }

    const data = await shodanRes.json() as {
      ip: string;
      ports: number[];
      hostnames: string[];
      cpes: string[];
      vulns: string[];
      tags: string[];
    };

    const COMMON_SERVICES: Record<number, string> = {
      21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
      80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
      993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
      3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
      6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
      27017: "MongoDB", 11211: "Memcached",
    };

    const ports = (data.ports || []).map((port: number) => {
      const exposure = CRITICAL_EXPOSED_PORTS[port];
      return {
        port,
        service: COMMON_SERVICES[port] || "Unknown",
        cpes: (data.cpes || []).filter((c: string) => c.includes(COMMON_SERVICES[port]?.toLowerCase() || "___")),
        vulns: [],
        exposureRisk: exposure?.risk,
        exposureReason: exposure?.reason,
      };
    });

    const highRiskOpenPorts = ports.filter(
      (p) => p.exposureRisk === "critical" || p.exposureRisk === "high",
    );

    const result: PortScanResult = {
      ip: data.ip || ip,
      ports,
      hostnames: data.hostnames || [hostname],
      totalVulns: (data.vulns || []).length,
    };

    const extra: Record<string, unknown> = {
      highRiskOpenPorts,
      highRiskOpenPortsCount: highRiskOpenPorts.length,
    };
    if (data.vulns?.length > 0) extra.cves = data.vulns;
    if (data.tags?.length > 0) extra.tags = data.tags;

    return NextResponse.json({ ...result, ...extra });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Port scan failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
