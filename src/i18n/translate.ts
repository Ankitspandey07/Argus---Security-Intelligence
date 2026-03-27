import type { Messages } from "./types";

/** Dot-path lookup e.g. "nav.scanner" */
export function translate(messages: Messages, path: string, vars?: Record<string, string | number>): string {
  const keys = path.split(".");
  let cur: unknown = messages;
  for (const k of keys) {
    if (cur === null || typeof cur !== "object" || !(k in (cur as object))) return path;
    cur = (cur as Record<string, unknown>)[k];
  }
  if (typeof cur !== "string") return path;
  let s = cur;
  if (vars) {
    for (const [vk, vv] of Object.entries(vars)) {
      s = s.replaceAll(`{${vk}}`, String(vv));
    }
  }
  return s;
}
