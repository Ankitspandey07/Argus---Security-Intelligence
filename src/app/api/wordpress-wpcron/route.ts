import { NextRequest, NextResponse } from "next/server";
import { readUrlBodyAndGuard } from "@/lib/route-helpers";
import { runWpCronChecks, runInfraMisconfigChecks } from "@/lib/infra-exposure-scan";

/**
 * WordPress wp-cron (Nuclei-style) plus infra probes: Swagger/OpenAPI, heapdump, Spring Actuator, Prometheus metrics.
 */

export async function POST(req: NextRequest) {
  try {
    const parsed = await readUrlBodyAndGuard(req);
    if (parsed instanceof NextResponse) return parsed;
    const origin = new URL(parsed.target.url).origin;

    const [checks, infraChecks] = await Promise.all([runWpCronChecks(origin), runInfraMisconfigChecks(origin)]);

    const anyWp = checks.some((c) => c.exposed);
    const infraExposed = infraChecks.filter((c) => c.exposed);
    const anyCriticalInfra = infraExposed.some((c) => c.severity === "critical");
    const anyHighInfra = infraExposed.some((c) => c.severity === "high");

    let severity: "high" | "medium" | "info" = "info";
    if (anyCriticalInfra || anyHighInfra) severity = "high";
    else if (anyWp || infraExposed.some((c) => c.severity === "medium")) severity = "medium";

    return NextResponse.json({
      origin,
      isWordPressCronInteresting: anyWp,
      infraExposedCount: infraExposed.length,
      severity,
      reference: "CVE-2023-22622 (wp-cron); Swagger/Actuator/Prometheus/heapdump heuristics (Nuclei-inspired)",
      checks,
      infraChecks,
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "wp-cron / infra check failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
