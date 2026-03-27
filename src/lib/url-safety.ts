/**
 * Reject URLs that could be used for SSRF against internal networks when
 * passed to outbound services (shorteners, etc.).
 */
export function isBlockedShortenHostname(hostname: string): boolean {
  const raw = hostname.trim().toLowerCase();
  if (!raw) return true;
  // IPv6 literals — block all (metadata, ULA, loopback, etc.)
  if (raw.startsWith("[")) return true;

  const h = raw.replace(/\.$/, "");

  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "0.0.0.0") return true;

  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (ipv4) {
    const a = Number(ipv4[1]);
    const b = Number(ipv4[2]);
    const c = Number(ipv4[3]);
    const d = Number(ipv4[4]);
    if ([a, b, c, d].some((n) => n > 255)) return true;
    if (a === 0 || a === 127) return true;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; /* CGNAT */
    if (a >= 224) return true; /* multicast / reserved */
    if (a === 198 && (b === 18 || b === 19)) return true; /* benchmark */
    if (a === 192 && b === 0 && c === 0) return true; /* IETF special */
    if (a === 192 && b === 0 && c === 2) return true; /* TEST-NET-1 */
    if (a === 255 && b === 255 && c === 255 && d === 255) return true;
  }

  if (h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".lan")) return true;

  return false;
}
