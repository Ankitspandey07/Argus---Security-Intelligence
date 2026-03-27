import type { Metadata } from "next";
import { cookies } from "next/headers";
import "./globals.css";
import { I18nProvider } from "@/components/I18nProvider";
import { getMessages } from "@/i18n/get-messages";
import { DEFAULT_LOCALE, LOCALES, LOCALE_BCP47, LOCALE_OG, type Locale } from "@/i18n/types";

const title = "Argus — Web & API Security Intelligence";
const description =
  "Deep security analysis for websites and APIs. Headers, SSL/TLS, DNS, ports, vulnerabilities, code review, and AI-powered insights.";

function parseLocale(v: string | undefined): Locale {
  if (v && (LOCALES as readonly string[]).includes(v)) return v as Locale;
  return DEFAULT_LOCALE;
}

function metadataBaseUrl(): URL {
  const raw =
    process.env.NEXT_PUBLIC_APP_URL?.trim() ||
    (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "http://localhost:3000");
  try {
    return new URL(raw);
  } catch {
    return new URL("http://localhost:3000");
  }
}

export async function generateMetadata(): Promise<Metadata> {
  const jar = await cookies();
  const locale = parseLocale(jar.get("argus_locale")?.value);
  const base = metadataBaseUrl();
  return {
    metadataBase: base,
    title,
    description,
    alternates: { canonical: "/" },
    openGraph: {
      title,
      description,
      url: base,
      siteName: "Argus",
      locale: LOCALE_OG[locale],
      type: "website",
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
    },
  };
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const jar = await cookies();
  const locale = parseLocale(jar.get("argus_locale")?.value);
  const highContrast = jar.get("argus_high_contrast")?.value === "1";
  const messages = await getMessages(locale);

  return (
    <html lang={LOCALE_BCP47[locale]} className={highContrast ? "high-contrast" : undefined}>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="antialiased min-h-screen">
        <I18nProvider locale={locale} messages={messages} highContrast={highContrast}>
          {children}
        </I18nProvider>
      </body>
    </html>
  );
}
