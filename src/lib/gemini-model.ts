/**
 * Stable default for Google AI Studio / Gemini API generateContent.
 * Override with GEMINI_MODEL in .env.local if needed (e.g. gemini-2.5-flash).
 */
export const GEMINI_FLASH_MODEL =
  process.env.GEMINI_MODEL?.trim() || "gemini-2.0-flash";
