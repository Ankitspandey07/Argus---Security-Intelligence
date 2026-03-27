/**
 * Structured audit line when ARGUS_AUDIT_LOG=1 (server logs only).
 */
export function argusAudit(event: string, meta: Record<string, unknown> = {}): void {
  if (process.env.ARGUS_AUDIT_LOG !== "1" && process.env.ARGUS_AUDIT_LOG !== "true") return;
  try {
    console.log(
      JSON.stringify({
        argus_audit: true,
        ts: new Date().toISOString(),
        event,
        ...meta,
      }),
    );
  } catch {
    /* ignore */
  }
}
