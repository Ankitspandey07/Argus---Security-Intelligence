import type { SSLResult } from "@/lib/types";

const TTL_MS = Math.min(300_000, Math.max(15_000, parseInt(process.env.ARGUS_SSL_CACHE_TTL_MS || "60000", 10) || 60_000));
const store = new Map<string, { exp: number; data: SSLResult }>();

export function getSslCached(hostname: string): SSLResult | null {
  if (process.env.ARGUS_SSL_CACHE === "0") return null;
  const e = store.get(hostname.toLowerCase());
  if (!e || Date.now() > e.exp) {
    if (e) store.delete(hostname.toLowerCase());
    return null;
  }
  return e.data;
}

export function setSslCached(hostname: string, data: SSLResult): void {
  if (process.env.ARGUS_SSL_CACHE === "0") return;
  const k = hostname.toLowerCase();
  store.set(k, { exp: Date.now() + TTL_MS, data });
  if (store.size > 400) {
    const now = Date.now();
    for (const [key, v] of store) {
      if (now > v.exp) store.delete(key);
    }
  }
}
