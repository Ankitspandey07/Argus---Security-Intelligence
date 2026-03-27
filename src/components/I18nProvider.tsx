"use client";

import { createContext, useCallback, useContext, useMemo } from "react";
import { useRouter } from "next/navigation";
import { LOCALE_BCP47, type Locale, type Messages } from "@/i18n/types";
import { translate } from "@/i18n/translate";

type Ctx = {
  locale: Locale;
  messages: Messages;
  t: (path: string, vars?: Record<string, string | number>) => string;
  formatDateTime: (iso: string) => string;
  setLocale: (locale: Locale) => void;
  setHighContrast: (on: boolean) => void;
  highContrast: boolean;
};

const I18nContext = createContext<Ctx | null>(null);

function setCookie(name: string, value: string) {
  document.cookie = `${name}=${encodeURIComponent(value)};path=/;max-age=31536000;SameSite=Lax`;
}

export function I18nProvider({
  children,
  locale,
  messages,
  highContrast,
}: {
  children: React.ReactNode;
  locale: Locale;
  messages: Messages;
  highContrast: boolean;
}) {
  const router = useRouter();

  const t = useCallback(
    (path: string, vars?: Record<string, string | number>) => translate(messages, path, vars),
    [messages],
  );

  const formatDateTime = useCallback(
    (iso: string) => {
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return iso;
      return new Intl.DateTimeFormat(LOCALE_BCP47[locale], {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(d);
    },
    [locale],
  );

  const setLocale = useCallback(
    (next: Locale) => {
      setCookie("argus_locale", next);
      router.refresh();
    },
    [router],
  );

  const setHighContrast = useCallback(
    (on: boolean) => {
      setCookie("argus_high_contrast", on ? "1" : "0");
      router.refresh();
    },
    [router],
  );

  const value = useMemo(
    () => ({ locale, messages, t, formatDateTime, setLocale, setHighContrast, highContrast }),
    [locale, messages, t, formatDateTime, setLocale, setHighContrast, highContrast],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): Ctx {
  const c = useContext(I18nContext);
  if (!c) throw new Error("useI18n must be used within I18nProvider");
  return c;
}
