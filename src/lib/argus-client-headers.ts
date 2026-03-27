/** localStorage key for optional shared-host API auth (sent as x-argus-key). */
export const ARGUS_API_KEY_STORAGE = "argus_server_api_key";

export function getArgusClientHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  try {
    const k = localStorage.getItem(ARGUS_API_KEY_STORAGE)?.trim();
    if (k) return { "x-argus-key": k };
  } catch {
    /* private mode */
  }
  return {};
}

export function jsonHeadersWithArgus(): Record<string, string> {
  return { "Content-Type": "application/json", ...getArgusClientHeaders() };
}
