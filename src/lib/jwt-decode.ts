/** Decode JWT payload without verification (inspection only). */

export function decodeJwtParts(token: string): { header: unknown; payload: unknown; signature: string } | null {
  const parts = token.trim().split(".");
  if (parts.length !== 3) return null;
  try {
    const decodeB64Url = (s: string) => {
      let b = s.replace(/-/g, "+").replace(/_/g, "/");
      const pad = 4 - (b.length % 4);
      if (pad !== 4) b += "=".repeat(pad);
      return JSON.parse(Buffer.from(b, "base64").toString("utf8"));
    };
    return {
      header: decodeB64Url(parts[0]),
      payload: decodeB64Url(parts[1]),
      signature: parts[2],
    };
  } catch {
    return null;
  }
}
