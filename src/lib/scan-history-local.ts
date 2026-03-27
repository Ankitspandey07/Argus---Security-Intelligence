const STORAGE_V2 = "argus_scan_history_v2";
const STORAGE_V1 = "argus_scan_history_v1";
const OWNER_KEY = "argus_scan_owner_v1";

/** Entries older than this are removed on every read/write (not uploaded anywhere). */
export const SCAN_HISTORY_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export const MAX_SCAN_HISTORY = 50;

export interface ScanHistoryEntry {
  id: string;
  savedAt: string;
  label: string;
  target: string;
  /** Anonymous id for this browser profile — other profiles on the same machine do not see these runs. */
  ownerId: string;
  /** JSON-roundtripped scan snapshot */
  snapshot: Record<string, unknown>;
}

function entrySavedMs(e: ScanHistoryEntry): number {
  const t = new Date(e.savedAt).getTime();
  return Number.isFinite(t) ? t : 0;
}

function isExpired(e: ScanHistoryEntry, now: number): boolean {
  return now - entrySavedMs(e) > SCAN_HISTORY_TTL_MS;
}

/** Stable random id per browser storage partition (normal vs private window are separate). */
export function getOrCreateScanOwnerId(): string {
  if (typeof window === "undefined") return "";
  try {
    let id = localStorage.getItem(OWNER_KEY);
    if (!id || id.length < 8) {
      id = crypto.randomUUID();
      localStorage.setItem(OWNER_KEY, id);
    }
    return id;
  } catch {
    try {
      let sid = sessionStorage.getItem(OWNER_KEY);
      if (!sid || sid.length < 8) {
        sid = crypto.randomUUID();
        sessionStorage.setItem(OWNER_KEY, sid);
      }
      return sid;
    } catch {
      return "argus-owner-fallback";
    }
  }
}

function parseEntries(json: string, ownerForLegacy: string): ScanHistoryEntry[] {
  try {
    const v = JSON.parse(json) as unknown;
    if (!Array.isArray(v)) return [];
    const out: ScanHistoryEntry[] = [];
    for (const x of v) {
      if (typeof x !== "object" || x === null) continue;
      const o = x as Record<string, unknown>;
      if (typeof o.id !== "string" || typeof o.savedAt !== "string" || typeof o.target !== "string") continue;
      if (typeof o.snapshot !== "object" || o.snapshot === null) continue;
      const label = typeof o.label === "string" ? o.label : o.target;
      const ownerId =
        typeof o.ownerId === "string" && o.ownerId.length >= 8 ? o.ownerId : ownerForLegacy;
      out.push({
        id: o.id,
        savedAt: o.savedAt,
        label: label.slice(0, 200),
        target: o.target.slice(0, 500),
        ownerId,
        snapshot: o.snapshot as Record<string, unknown>,
      });
    }
    return out;
  } catch {
    return [];
  }
}

function persistAll(entries: ScanHistoryEntry[]) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(STORAGE_V2, JSON.stringify(entries));
  } catch {
    /* quota */
  }
}

/**
 * Load from disk, migrate v1 once, drop expired rows, write back.
 * Returns the full stored list (all owners), newest-first not guaranteed.
 */
function readNormalizePersist(): ScanHistoryEntry[] {
  if (typeof window === "undefined") return [];
  const owner = getOrCreateScanOwnerId();
  let raw = localStorage.getItem(STORAGE_V2);
  let rows: ScanHistoryEntry[] = [];
  if (raw) {
    rows = parseEntries(raw, owner);
  } else {
    const legacy = localStorage.getItem(STORAGE_V1);
    if (legacy) {
      rows = parseEntries(legacy, owner);
      localStorage.removeItem(STORAGE_V1);
    }
  }
  const now = Date.now();
  rows = rows.filter((e) => !isExpired(e, now));
  persistAll(rows);
  return rows;
}

/** Recent scans for this browser profile only, newest first, capped. */
export function loadScanHistory(): ScanHistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const owner = getOrCreateScanOwnerId();
    const all = readNormalizePersist();
    return all
      .filter((e) => e.ownerId === owner)
      .sort((a, b) => entrySavedMs(b) - entrySavedMs(a))
      .slice(0, MAX_SCAN_HISTORY);
  } catch {
    return [];
  }
}

export function pushScanHistory(input: {
  target: string;
  label?: string;
  snapshot: Record<string, unknown>;
}): ScanHistoryEntry[] {
  if (typeof window === "undefined") return [];
  const owner = getOrCreateScanOwnerId();
  const all = readNormalizePersist();
  const entry: ScanHistoryEntry = {
    id: crypto.randomUUID(),
    savedAt: new Date().toISOString(),
    label: (input.label ?? input.target).slice(0, 200),
    target: input.target.slice(0, 500),
    ownerId: owner,
    snapshot: input.snapshot,
  };
  const others = all.filter((e) => e.ownerId !== owner);
  const mine = all
    .filter((e) => e.ownerId === owner)
    .sort((a, b) => entrySavedMs(b) - entrySavedMs(a));
  const nextMine = [entry, ...mine].slice(0, MAX_SCAN_HISTORY);
  persistAll([...others, ...nextMine]);
  return loadScanHistory();
}

export function removeScanHistoryEntry(id: string): ScanHistoryEntry[] {
  if (typeof window === "undefined") return [];
  const owner = getOrCreateScanOwnerId();
  const all = readNormalizePersist();
  const next = all.filter((e) => !(e.id === id && e.ownerId === owner));
  persistAll(next);
  return loadScanHistory();
}

export function updateScanHistoryLabel(id: string, label: string): ScanHistoryEntry[] {
  if (typeof window === "undefined") return [];
  const owner = getOrCreateScanOwnerId();
  const all = readNormalizePersist();
  const next = all.map((e) =>
    e.id === id && e.ownerId === owner ? { ...e, label: label.slice(0, 200) } : e,
  );
  persistAll(next);
  return loadScanHistory();
}

/** Remove every saved run for this browser profile only. */
export function clearScanHistoryForCurrentOwner(): ScanHistoryEntry[] {
  if (typeof window === "undefined") return [];
  const owner = getOrCreateScanOwnerId();
  const all = readNormalizePersist();
  persistAll(all.filter((e) => e.ownerId !== owner));
  return [];
}

/** Human-readable TTL for UI copy. */
export function scanHistoryTtlDays(): number {
  return Math.round(SCAN_HISTORY_TTL_MS / (24 * 60 * 60 * 1000));
}
