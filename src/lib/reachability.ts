/** Shared messages when the primary HTTP scan cannot load the target page. */

export type UnreachableCode = "dns_failed" | "connection_failed";

export type UnreachableBody = {
  unreachable: true;
  code: UnreachableCode;
  title: string;
  detail: string;
  error: string;
};

export function connectionFailureMessage(err: unknown): { title: string; detail: string; error: string } {
  const msg = err instanceof Error ? err.message : String(err);
  const lower = msg.toLowerCase();
  if (err instanceof Error && err.name === "AbortError") {
    return {
      title: "Timed out",
      detail: "No response within 15 seconds. The host may be down, firewalled, or too slow.",
      error: "Connection timed out",
    };
  }
  if (lower.includes("enotfound") || lower.includes("getaddrinfo")) {
    return {
      title: "Host not found",
      detail: "DNS lookup failed. Check spelling or try again later.",
      error: msg,
    };
  }
  if (lower.includes("econnrefused")) {
    return {
      title: "Connection refused",
      detail: "Nothing accepted the connection on this address/port. The service may be down.",
      error: msg,
    };
  }
  if (lower.includes("certificate") || lower.includes("ssl") || lower.includes("tls")) {
    return {
      title: "TLS / certificate error",
      detail: "HTTPS handshake failed. Wrong hostname, expired cert, or TLS-only mismatch (try http vs https).",
      error: msg,
    };
  }
  return {
    title: "Cannot reach host",
    detail: "The request failed before a normal HTTP response. Verify the URL, protocol, and that the site is up.",
    error: msg,
  };
}
