# Argus — Web & API Security Intelligence

**Author:** [Ankit Pandey](https://github.com/Ankitspandey07)

**Live demo:** [argus-security-intelligence.vercel.app](https://argus-security-intelligence.vercel.app/)

---

> **GitHub “About” description** (paste under repository name → *Edit* → Description, ~350 characters max):
>
> *Web & API posture scanner: security headers, TLS, DNS & mail auth, exposed ports (Shodan), subdomains, source/JS secret patterns, takeover checks, optional VirusTotal & Gemini—Next.js, no database.*

---

## What is Argus?

**Argus** is a **browser + server** security tool for **websites, APIs, and hosts** you are **authorized** to test. You enter a URL, domain, or IP; the app runs **real checks** (not a mock) through **Next.js API routes** and shows results in one dashboard.

### The headline: “MobSF for mobile — what about the web?”

| Layer | Mobile world | Web / API / IP (Argus) |
|--------|----------------|-------------------------|
| **Static-style analysis** | MobSF decompiles APK/IPA, scans binaries & manifests | Argus grades **HTTP security headers** & **cookies**, reads **robots.txt** / **security.txt**, **crawls HTML/JS** for **secrets & risky patterns**, matches **front-end library versions** (Retire.js-style CVE hints), and runs a **heuristic SAST** in the **Code review** workspace |
| **Network / transport** | TLS, cleartext traffic | **SSL/TLS** probe (cert, chain, common misconfigs) |
| **Attack surface / intel** | Permissions, exported components | **Subdomains** (e.g. crt.sh), **open ports** & tags via **Shodan InternetDB**, optional **VirusTotal** domain context, **CNAME takeover** heuristics, **WordPress / infra** exposure checks |
| **Mail & identity** | — | **SPF / DMARC** DNS for the domain |
| **Reporting** | MobSF PDF/report | **Export**: JSON snapshot, **CSV**, **SARIF** subset, **PDF** (with optional **Gemini** narrative when configured) |

Argus is **not** a full DAST proxy like OWASP ZAP or Burp Suite, and **not** a mobile analyzer like MobSF. It **complements** them: **fast posture + recon + secret/source signals** for **web and API endpoints** and **IPs**, with **no signup and no database**—state stays in the browser unless you export.

---

## What it does (modules)

Scans are grouped into **Quick** (fast, fewer third-party calls) and **Complete** (full pipeline).

| Area | What Argus checks |
|------|-------------------|
| **Headers & cookies** | OWASP-aligned security headers, grading, cookie issues |
| **SSL / TLS** | Certificate and TLS configuration signals |
| **Mail auth** | SPF & DMARC DNS records |
| **Site files** | `robots.txt`, `security.txt` |
| **Ports** | High-risk / exposed services via **Shodan InternetDB** (IP/host context) |
| **Subdomains** | Discovery (e.g. certificate transparency) |
| **Source & secrets** | **Complete** only: crawl pages & JS for keys, JWTs, suspicious strings |
| **VirusTotal** | **Complete** + API key: domain report with summarized risk (optional raw JSON) |
| **Google dork** | **Complete** + Google CSE API: search exposure hints |
| **Takeover** | CNAME / dangling-style heuristics (apex quick scan; deeper compare in UI history) |
| **WP / infra** | `wp-cron.php` & related exposure patterns (Nuclei-aligned ideas) |
| **Libraries** | Version & **Retire.js**-style CVE associations where data exists |
| **AI report** | **Complete** + `GEMINI_API_KEY`: consolidated narrative |
| **Tools workspace** | JWT / Base64 / hex decode, **static code review** (heuristic SAST; optional Semgrep **only** where CLI is installed) |

See `src/lib/scan-presets.ts` for exactly which modules run in **Quick** vs **Complete**.

---

## Tech stack

- **Next.js** (App Router) + **React** + **TypeScript** + **Tailwind CSS**
- **API routes** perform outbound scans (HTTP, DNS, TLS, optional third-party APIs)
- **No database**; scan history is **localStorage** on the device
- Optional **pdf-lib** PDFs, **@google/genai** for Gemini

---

## Quick start

```bash
cd argus
cp .env.example .env.local
# Edit .env.local — e.g. GEMINI_API_KEY, VIRUSTOTAL_API_KEY (optional)
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Dev server issues (500 / “page isn’t working”)

Turbopack’s `.next` cache can rarely corrupt after crashes.

```bash
npm run dev:clean
# or: rm -rf .next && npm run dev
```

If port `3000` is busy: `npx next dev -p 3001`.

---

## Deploy (public, free-friendly)

Argus needs a **Node** host (API routes). **Good fits:**

- **[Vercel](https://vercel.com)** — import this repo; set env vars in the dashboard ([live example](https://argus-security-intelligence.vercel.app/)).
- **Netlify**, **Render**, **Railway**, **Fly.io**, or a small **VPS** with `npm run build && npm run start`.

**Not suitable:** **GitHub Pages** (static only), **PythonAnywhere** (Python WSGI; not a Node server).

**Health check:** `GET /api/health` → `{ "ok": true, "service": "argus", ... }`.

### Recommended environment variables (production)

| Variable | Purpose |
|----------|---------|
| `NEXT_PUBLIC_APP_URL` | Canonical site URL (Open Graph / metadata), e.g. `https://your-app.vercel.app` |
| `ARGUS_API_KEY` | If set, clients must send `x-argus-key` or `Bearer` — **strongly recommended** for public URLs |
| `GEMINI_API_KEY` | Optional AI summary |
| `VIRUSTOTAL_API_KEY` | Optional VirusTotal module |
| `GOOGLE_CSE_API_KEY` + `GOOGLE_CSE_ID` | Optional Google dork module |
| `ARGUS_ALLOWED_DOMAINS` | Optional restrict scan targets to your domains |
| `ARGUS_RATE_LIMIT_*` | Tune per-IP limits |

**Semgrep** (`ARGUS_ENABLE_SEMGREP`) is for machines where the `semgrep` CLI is installed; **not** on default Vercel serverless.

Full list and comments: [`.env.example`](./.env.example).

---

## Static analysis in Argus (where “SAST” lives)

- **Heuristic rules** for pasted/uploaded code: `src/lib/sast-static-scan.ts`
- **Maintainer docs** (rules, languages, false positives): [`docs/sast-rules.md`](./docs/sast-rules.md)

---

## Security

- **Never commit secrets.** Use `.env.local` (gitignored) or your host’s secret store.
- If a key was ever exposed, **rotate** it in [Google AI Studio](https://aistudio.google.com/apikey) and [VirusTotal](https://www.virustotal.com/) as applicable.
- **Public deployments:** set `ARGUS_API_KEY`, tighten rate limits, consider `ARGUS_ALLOWED_DOMAINS`, monitor logs and provider ToS (VirusTotal, Shodan InternetDB, Gemini).

---

## Legal

Only scan systems you are **explicitly authorized** to test. VirusTotal use must comply with the [VirusTotal Terms of Service](https://www.virustotal.com/gui/terms-of-service).

---

## License / contributions

This project is provided as-is for security research and authorized testing. Issues and PRs welcome via GitHub.
