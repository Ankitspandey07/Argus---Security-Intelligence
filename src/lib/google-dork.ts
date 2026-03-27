/**
 * Google-style "dork" queries for a target. Automated results require Google Programmable Search (Custom Search JSON API).
 * Without API keys, callers get ready-made Google search URLs for manual review (respect Google ToS for automated scraping).
 */

export type DorkDefinition = {
  id: string;
  title: string;
  /** Short explanation for the UI */
  description: string;
  /** Builds the `q` parameter */
  buildQuery: (site: string) => string;
};

export const GOOGLE_DORKS: DorkDefinition[] = [
  {
    id: "pdf",
    title: "Indexed PDFs",
    description: "PDFs that may leak internal docs.",
    buildQuery: (s) => `site:${s} filetype:pdf`,
  },
  {
    id: "sql",
    title: "SQL / dumps",
    description: "Database dumps indexed by mistake.",
    buildQuery: (s) => `site:${s} (filetype:sql OR filetype:dump)`,
  },
  {
    id: "env",
    title: ".env / secrets in URL",
    description: "Paths mentioning env or credentials.",
    buildQuery: (s) => `site:${s} (inurl:.env OR inurl:config OR inurl:credentials)`,
  },
  {
    id: "admin",
    title: "Admin / login surfaces",
    description: "Common admin entry points.",
    buildQuery: (s) => `site:${s} (inurl:admin OR inurl:login OR inurl:wp-admin)`,
  },
  {
    id: "api-docs",
    title: "API documentation",
    description: "Swagger/OpenAPI or docs exposed to search.",
    buildQuery: (s) => `site:${s} (inurl:swagger OR inurl:api-docs OR inurl:openapi)`,
  },
  {
    id: "backup",
    title: "Backups & archives",
    description: "Zip/tar/bak files.",
    buildQuery: (s) => `site:${s} (filetype:bak OR filetype:zip OR filetype:tar OR filetype:gz)`,
  },
  {
    id: "s3-ref",
    title: "AWS / S3 references",
    description: "Pages referencing S3 or ARNs (often benign).",
    buildQuery: (s) => `site:${s} (s3.amazonaws.com OR arn:aws:s3 OR "x-amz-")`,
  },
  {
    id: "git",
    title: "Git / repo hints",
    description: "Accidental .git or github references.",
    buildQuery: (s) => `site:${s} (inurl:.git OR "github.com" filetype:json)`,
  },
];

export function googleSearchUrl(query: string): string {
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

export type CseHit = {
  title: string;
  link: string;
  snippet?: string;
  dorkId: string;
  dorkTitle: string;
};

export async function runGoogleCseForDorks(
  site: string,
  apiKey: string,
  cx: string,
  maxQueries = 8,
): Promise<{ hits: CseHit[]; errors: string[] }> {
  const hits: CseHit[] = [];
  const errors: string[] = [];
  const subset = GOOGLE_DORKS.slice(0, maxQueries);

  for (const d of subset) {
    const q = d.buildQuery(site);
    const url = new URL("https://www.googleapis.com/customsearch/v1");
    url.searchParams.set("key", apiKey);
    url.searchParams.set("cx", cx);
    url.searchParams.set("q", q);
    url.searchParams.set("num", "5");

    try {
      const res = await fetch(url.toString(), { signal: AbortSignal.timeout(12_000) });
      const data = (await res.json()) as {
        error?: { message?: string };
        items?: { title?: string; link?: string; snippet?: string }[];
      };
      if (!res.ok) {
        errors.push(`${d.id}: ${data.error?.message || res.statusText}`);
        continue;
      }
      for (const it of data.items ?? []) {
        if (it.link && it.title) {
          hits.push({
            title: it.title,
            link: it.link,
            snippet: it.snippet,
            dorkId: d.id,
            dorkTitle: d.title,
          });
        }
      }
    } catch (e: unknown) {
      errors.push(`${d.id}: ${e instanceof Error ? e.message : "request failed"}`);
    }
  }

  return { hits, errors };
}
