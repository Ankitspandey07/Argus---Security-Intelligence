import { NextResponse } from "next/server";

/**
 * Liveness for load balancers / uptime monitors. Intentionally unauthenticated and not rate-limited.
 * Do not expose sensitive data here.
 */
export async function GET() {
  return NextResponse.json({
    ok: true,
    service: "argus",
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
}
