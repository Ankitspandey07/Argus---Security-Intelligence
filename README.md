# Argus — Web & API Security Intelligence

**Author:** Ankit Pandey  

Next.js app: live header/TLS/DNS scans, same-origin source & JS secret pattern scan, subdomain discovery, Shodan InternetDB ports, optional **VirusTotal** domain report (with automatic risk summaries + expandable raw JSON), **quick apex-only takeover** during the main scan plus **on-demand full-subdomain takeover** analysis (up to 150 hosts), WordPress `wp-cron.php` checks (Nuclei-aligned), **Retire.js** CVE matching plus a **full library inventory** (passed / failed / warnings), JWT/Base64/hex decode tool, Gemini-powered reporting, and a **color PDF export** (score bars, plain-English Gemini blurbs when `GEMINI_API_KEY` is set).

## Setup

```bash
cd argus
cp .env.example .env.local
# Edit .env.local — add GEMINI_API_KEY and optionally VIRUSTOTAL_API_KEY
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Hosting publicly (free tiers, no database)

Argus is a **Next.js** app with **API routes** — it needs a **Node** runtime. Good fits:

- **[Vercel](https://vercel.com)** — connect the GitHub repo; set env vars in the dashboard.
- **[Netlify](https://netlify.com)** or **[Render](https://render.com)** — similar, use their Next/Node guides.

**GitHub Pages** only serves static files and **cannot** run this project’s scanners. **PythonAnywhere** targets Python WSGI; running Node/Next there is non-standard — prefer Vercel/Netlify for the least friction.

Optional env vars for a public instance: `GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, `ARGUS_API_KEY` (shared key for visitors), `ARGUS_RATE_LIMIT_*`, `ARGUS_ALLOWED_DOMAINS` (if you want to restrict targets).

### Dev server shows “This page isn’t working” / HTTP 500

Turbopack’s cache under `.next` can rarely corrupt after crashes or interrupted builds. Fix:

```bash
# Stop any running `next dev` (Ctrl+C), then:
npm run dev:clean
# or: rm -rf .next && npm run dev
```

If port 3000 is stuck, quit the old process or use another port: `npx next dev -p 3001`.

## Code review (static SAST)

Heuristic rules live in `src/lib/sast-static-scan.ts`. **Maintainers:** full rule tables, language packs, false-positive notes, and how to extend the scanner are documented in **[docs/sast-rules.md](./docs/sast-rules.md)**.

## Security

- **Never paste API keys into chat, tickets, or source files.** Put `GEMINI_API_KEY` and `VIRUSTOTAL_API_KEY` only in `.env.local` (gitignored).  
- If a key was exposed anywhere public, **rotate it immediately** in [Google AI Studio](https://aistudio.google.com/apikey) and VirusTotal.  
- Optional: set `GEMINI_MODEL` (default `gemini-2.0-flash`) if your project supports a different model ID.

### Hardening a public deployment

- Set **`ARGUS_API_KEY`** and distribute it only to trusted users; they paste it once in the app (stored in `localStorage` as `argus_server_api_key`) so your API routes are not wide open.  
- Tighten **`ARGUS_RATE_LIMIT_*`** for untrusted traffic; defaults are permissive.  
- Use **`ARGUS_ALLOWED_DOMAINS`** if the instance should only scan your own zones.  
- **Outbound scans** (`/api/scan`, ports, subdomains, etc.) are abuse-prone: monitor costs, logs, and provider ToS (VirusTotal, Shodan InternetDB, Gemini).  
- **Semgrep** (`ARGUS_ENABLE_SEMGREP=1`) runs a subprocess on user-supplied code — enable only on locked-down hosts; keep Semgrep updated.

## Legal

Only scan targets you are authorized to test. VirusTotal use must comply with [VirusTotal Terms of Service](https://www.virustotal.com/gui/terms-of-service).
