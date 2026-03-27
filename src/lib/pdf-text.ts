/**
 * pdf-lib StandardFonts (Helvetica) use WinAnsi encoding — many Unicode chars break or must be mapped.
 * Replace common punctuation with ASCII; strip remaining non-Latin-1-safe chars (do NOT use "?" placeholders).
 */
export function sanitizePdfText(s: string): string {
  return s
    .replace(/\r\n/g, "\n")
    .replace(/\u2014|\u2013|\u2212|\u2010/g, "-") // dashes
    .replace(/\u2018|\u2019|\u02BC|\u00B4/g, "'")
    .replace(/\u201C|\u201D|\u00AB|\u00BB/g, '"')
    .replace(/\u2026/g, "...")
    .replace(/\u00A0|\u202F|\u2007/g, " ")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\u00B7/g, "*") // middle dot
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^\n\t\x20-\x7E]/g, ""); // drop unmappable chars (cleaner than "?")
}
