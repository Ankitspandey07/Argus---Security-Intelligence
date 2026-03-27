/** Shared types for mail-auth and site-meta API responses (used by UI + routes). */

export interface MailAuthResult {
  hostname: string;
  checkedHosts: string[];
  mx: { exchange: string; priority: number }[];
  spf: { host: string; record: string } | null;
  dmarc: { host: string; record: string } | null;
  notes: string[];
}

export interface FetchedMeta {
  path: string;
  finalUrl: string;
  status: number;
  contentType: string | null;
  accessControlAllowOrigin: string | null;
  excerpt: string;
  bytes: number;
}

export interface SiteMetaResult {
  origin: string;
  robots: FetchedMeta | { skipped: true; reason: string };
  securityTxt: FetchedMeta | { skipped: true; reason: string };
}
