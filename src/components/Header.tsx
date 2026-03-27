"use client";

import { Shield, Github, Linkedin, Contrast } from "lucide-react";
import { useI18n } from "@/components/I18nProvider";
import { LOCALES, LOCALE_LABELS, type Locale } from "@/i18n/types";

const GITHUB = "https://github.com/ankitspandey07";
const LINKEDIN = "https://www.linkedin.com/in/ankits-pandey07/";

export default function Header() {
  const { t, locale, setLocale, highContrast, setHighContrast } = useI18n();

  return (
    <header className="border-b border-border bg-surface/60 backdrop-blur-xl sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 min-h-16 py-2 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-accent/15 flex items-center justify-center">
            <Shield className="w-5 h-5 text-accent" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white leading-none">{t("brand.title")}</h1>
            <span className="text-[10px] font-medium text-text-muted tracking-wider uppercase">
              {t("brand.tagline")}
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3">
          <div className="flex items-center gap-1.5 rounded-lg border border-border bg-bg/80 px-2 py-1">
            <label htmlFor="argus-locale" className="sr-only">
              {t("prefs.language")}
            </label>
            <select
              id="argus-locale"
              value={locale}
              onChange={(e) => setLocale(e.target.value as Locale)}
              className="bg-transparent text-[11px] text-text-muted focus:outline-none focus:ring-1 focus:ring-accent/50 rounded cursor-pointer max-w-[12rem] sm:max-w-[14rem]"
              title={t("prefs.localeHint")}
            >
              {LOCALES.map((loc) => (
                <option key={loc} value={loc} className="bg-surface text-white">
                  {LOCALE_LABELS[loc]}
                </option>
              ))}
            </select>
          </div>

          <button
            type="button"
            onClick={() => setHighContrast(!highContrast)}
            aria-pressed={highContrast}
            title={t("prefs.highContrast")}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
              highContrast
                ? "border-accent bg-accent/20 text-accent"
                : "border-border bg-bg/80 text-text-muted hover:text-white hover:border-border-hover"
            }`}
          >
            <Contrast className="w-3.5 h-3.5 shrink-0" aria-hidden />
            <span className="hidden sm:inline">{t("prefs.highContrast")}</span>
          </button>

          <span className="hidden sm:inline text-xs text-text-dim font-mono">v1.0.0</span>
          <a
            href={LINKEDIN}
            target="_blank"
            rel="noopener noreferrer"
            className="text-text-dim hover:text-[#0A66C2] transition-colors"
            aria-label="Ankit Pandey on LinkedIn"
          >
            <Linkedin className="w-5 h-5" />
          </a>
          <a
            href={GITHUB}
            target="_blank"
            rel="noopener noreferrer"
            className="text-text-dim hover:text-white transition-colors"
            aria-label="Ankit Pandey on GitHub"
          >
            <Github className="w-5 h-5" />
          </a>
        </div>
      </div>
    </header>
  );
}
