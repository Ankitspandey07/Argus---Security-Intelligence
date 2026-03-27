import type en from "./messages/en.json";

export type Messages = typeof en;
export type Locale = "en" | "es" | "fr" | "de" | "pt" | "ja" | "hi" | "zh";

export const LOCALES: Locale[] = ["en", "es", "fr", "de", "pt", "ja", "hi", "zh"];
export const DEFAULT_LOCALE: Locale = "en";

export const LOCALE_LABELS: Record<Locale, string> = {
  en: "English",
  es: "Español",
  fr: "Français",
  de: "Deutsch",
  pt: "Português (Brasil)",
  ja: "日本語",
  hi: "हिन्दी",
  zh: "简体中文",
};

/** BCP 47 for `<html lang>`, `Intl`, etc. */
export const LOCALE_BCP47: Record<Locale, string> = {
  en: "en",
  es: "es",
  fr: "fr",
  de: "de",
  pt: "pt-BR",
  ja: "ja",
  hi: "hi",
  zh: "zh-CN",
};

/** Open Graph `locale` format */
export const LOCALE_OG: Record<Locale, string> = {
  en: "en_US",
  es: "es_ES",
  fr: "fr_FR",
  de: "de_DE",
  pt: "pt_BR",
  ja: "ja_JP",
  hi: "hi_IN",
  zh: "zh_CN",
};
