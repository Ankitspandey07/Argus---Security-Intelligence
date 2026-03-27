/**
 * Short, human-readable fragment from the scanned line (for UI / PDF / CSV).
 */
export function lineEvidenceSnippet(code: string, lineNumber: number, maxWords = 7): string | undefined {
  if (lineNumber < 1) return undefined;
  const lines = code.split("\n");
  const raw = lines[lineNumber - 1];
  if (raw == null) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  const words = trimmed.split(/\s+/).filter(Boolean);
  const slice = words.slice(0, maxWords).join(" ");
  return words.length > maxWords ? `${slice} ...` : slice;
}
