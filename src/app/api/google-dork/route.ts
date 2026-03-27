import { NextRequest, NextResponse } from "next/server";
import { readUrlBodyAndGuard } from "@/lib/route-helpers";
import { GOOGLE_DORKS, googleSearchUrl, runGoogleCseForDorks } from "@/lib/google-dork";

export async function POST(req: NextRequest) {
  try {
    const parsed = await readUrlBodyAndGuard(req);
    if (parsed instanceof NextResponse) return parsed;
    const hostname = parsed.target.hostname;
    const site = hostname.replace(/^www\./, "");

    const manualQueries = GOOGLE_DORKS.map((d) => ({
      id: d.id,
      title: d.title,
      description: d.description,
      query: d.buildQuery(site),
      googleUrl: googleSearchUrl(d.buildQuery(site)),
    }));

    const key = process.env.GOOGLE_CSE_API_KEY;
    const cx = process.env.GOOGLE_CSE_ID;

    if (key && cx) {
      const { hits, errors } = await runGoogleCseForDorks(site, key, cx, 8);
      return NextResponse.json({
        mode: "api" as const,
        site,
        manualQueries,
        hits,
        apiErrors: errors.length ? errors : undefined,
        note:
          "Results from Google Programmable Search API (Custom Search JSON). Daily free quota applies; duplicate URLs across dorks are possible.",
      });
    }

    return NextResponse.json({
      mode: "manual" as const,
      site,
      manualQueries,
      hits: [] as { title: string; link: string; snippet?: string; dorkId: string; dorkTitle: string }[],
      note:
        "Programmatic results require GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID (Google Programmable Search Engine). Until then, use the links below — only for targets you are authorized to assess. Automated scraping of Google is against their ToS.",
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Google dork module failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
