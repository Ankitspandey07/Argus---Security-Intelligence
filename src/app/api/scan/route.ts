import { NextRequest, NextResponse } from "next/server";
import net from "node:net";
import { gradeFromScore } from "@/lib/utils";
import { readUrlBodyAndGuard } from "@/lib/route-helpers";
import dns from "dns/promises";
import type { UnreachableBody } from "@/lib/reachability";
import { connectionFailureMessage } from "@/lib/reachability";
import { PRIMARY_SCAN_FETCH_HEADERS } from "@/lib/scanner-fetch-headers";
import type { HeaderResult, CookieResult, TechResult, ScanResult } from "@/lib/types";

const SECURITY_HEADERS: {
  name: string;
  key: string;
  severity: "critical" | "high" | "medium" | "low";
  weight: number;
  check: (value: string | null, allHeaders: Record<string, string>) => HeaderResult;
}[] = [
  {
    name: "Strict-Transport-Security",
    key: "strict-transport-security",
    severity: "high",
    weight: 15,
    check: (val) => {
      if (!val) return { name: "Strict-Transport-Security", status: "fail", value: "Missing", severity: "high", description: "HSTS header is not set. Browsers won't enforce HTTPS connections.", remediation: "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to enforce HTTPS." };
      const maxAge = val.match(/max-age=(\d+)/i);
      const age = maxAge ? parseInt(maxAge[1]) : 0;
      const hasSub = /includeSubDomains/i.test(val);
      if (age >= 31536000 && hasSub) return { name: "Strict-Transport-Security", status: "pass", value: val, severity: "high", description: "HSTS is properly configured with sufficient max-age and includeSubDomains.", remediation: "Properly configured." };
      return { name: "Strict-Transport-Security", status: "warn", value: val, severity: "high", description: `HSTS present but ${age < 31536000 ? "max-age is too low" : ""}${!hasSub ? " missing includeSubDomains" : ""}.`, remediation: "Set max-age to at least 31536000 (1 year) and add includeSubDomains." };
    },
  },
  {
    name: "Content-Security-Policy",
    key: "content-security-policy",
    severity: "critical",
    weight: 20,
    check: (val) => {
      if (!val) return { name: "Content-Security-Policy", status: "fail", value: "Missing", severity: "critical", description: "No CSP header. The site is vulnerable to XSS and data injection attacks.", remediation: "Implement a strict Content-Security-Policy. Start with `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';`" };
      const hasDefault = /default-src/i.test(val);
      const hasUnsafeInline = /unsafe-inline/i.test(val) && /script-src/i.test(val);
      if (hasDefault && !hasUnsafeInline) return { name: "Content-Security-Policy", status: "pass", value: val, severity: "critical", description: "CSP is set with a default-src directive and no unsafe-inline in scripts.", remediation: "Properly configured." };
      return { name: "Content-Security-Policy", status: "warn", value: val, severity: "critical", description: `CSP present but ${!hasDefault ? "lacks default-src" : ""}${hasUnsafeInline ? " allows unsafe-inline scripts" : ""}.`, remediation: "Tighten CSP: add default-src, remove unsafe-inline from script-src, use nonces or hashes." };
    },
  },
  {
    name: "X-Frame-Options",
    key: "x-frame-options",
    severity: "high",
    weight: 10,
    check: (val, all) => {
      const csp = all["content-security-policy"] || "";
      const hasFrameAncestors = /frame-ancestors/i.test(csp);
      if (!val && !hasFrameAncestors) return { name: "X-Frame-Options", status: "fail", value: "Missing", severity: "high", description: "No clickjacking protection. The site can be embedded in iframes by attackers.", remediation: "Set `X-Frame-Options: DENY` or `SAMEORIGIN`, or use CSP `frame-ancestors 'self'`." };
      if (val && /^(DENY|SAMEORIGIN)$/i.test(val.trim())) return { name: "X-Frame-Options", status: "pass", value: val, severity: "high", description: "Clickjacking protection is enabled.", remediation: "Properly configured." };
      if (hasFrameAncestors) return { name: "X-Frame-Options", status: "pass", value: "Via CSP frame-ancestors", severity: "high", description: "Clickjacking protection via CSP frame-ancestors directive.", remediation: "Properly configured." };
      return { name: "X-Frame-Options", status: "warn", value: val || "Missing", severity: "high", description: "X-Frame-Options has a non-standard value.", remediation: "Set to DENY or SAMEORIGIN." };
    },
  },
  {
    name: "X-Content-Type-Options",
    key: "x-content-type-options",
    severity: "medium",
    weight: 10,
    check: (val) => {
      if (!val) return { name: "X-Content-Type-Options", status: "fail", value: "Missing", severity: "medium", description: "Missing nosniff header. Browsers may MIME-sniff responses, leading to attacks.", remediation: "Set `X-Content-Type-Options: nosniff`." };
      if (val.toLowerCase() === "nosniff") return { name: "X-Content-Type-Options", status: "pass", value: val, severity: "medium", description: "MIME type sniffing is prevented.", remediation: "Properly configured." };
      return { name: "X-Content-Type-Options", status: "warn", value: val, severity: "medium", description: "Non-standard value for X-Content-Type-Options.", remediation: "Set to `nosniff`." };
    },
  },
  {
    name: "Referrer-Policy",
    key: "referrer-policy",
    severity: "medium",
    weight: 10,
    check: (val) => {
      if (!val) return { name: "Referrer-Policy", status: "fail", value: "Missing", severity: "medium", description: "No Referrer-Policy set. Full URLs may leak in Referer headers to third parties.", remediation: "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`." };
      const safe = ["strict-origin-when-cross-origin", "no-referrer", "same-origin", "strict-origin", "no-referrer-when-downgrade"];
      if (safe.some(s => val.toLowerCase().includes(s))) return { name: "Referrer-Policy", status: "pass", value: val, severity: "medium", description: "Referrer-Policy is set to a secure value.", remediation: "Properly configured." };
      return { name: "Referrer-Policy", status: "warn", value: val, severity: "medium", description: "Referrer-Policy is set but may leak information.", remediation: "Consider `strict-origin-when-cross-origin`." };
    },
  },
  {
    name: "Permissions-Policy",
    key: "permissions-policy",
    severity: "medium",
    weight: 10,
    check: (val) => {
      if (!val) return { name: "Permissions-Policy", status: "fail", value: "Missing", severity: "medium", description: "No Permissions-Policy. Browser features like camera, microphone, geolocation are unrestricted.", remediation: "Set Permissions-Policy to restrict unused browser features, e.g., `camera=(), microphone=(), geolocation=()`." };
      return { name: "Permissions-Policy", status: "pass", value: val.substring(0, 100) + (val.length > 100 ? "..." : ""), severity: "medium", description: "Permissions-Policy restricts browser feature access.", remediation: "Properly configured." };
    },
  },
  {
    name: "X-XSS-Protection",
    key: "x-xss-protection",
    severity: "low",
    weight: 5,
    check: (val) => {
      if (!val) return { name: "X-XSS-Protection", status: "warn", value: "Missing", severity: "low", description: "Legacy XSS protection header not set. Modern browsers use CSP instead, but this helps older browsers.", remediation: "Set `X-XSS-Protection: 0` (with strong CSP) or `1; mode=block` (without CSP)." };
      return { name: "X-XSS-Protection", status: "pass", value: val, severity: "low", description: "Legacy XSS auditor header is set.", remediation: "Properly configured." };
    },
  },
  {
    name: "Cache-Control",
    key: "cache-control",
    severity: "low",
    weight: 5,
    check: (val) => {
      if (!val) return { name: "Cache-Control", status: "warn", value: "Missing", severity: "low", description: "No Cache-Control header. Sensitive data may be cached by proxies or browsers.", remediation: "Set appropriate Cache-Control directives for sensitive endpoints: `no-store, no-cache, must-revalidate`." };
      return { name: "Cache-Control", status: "pass", value: val, severity: "low", description: "Cache-Control header is present.", remediation: "Properly configured." };
    },
  },
  {
    name: "Server Header",
    key: "server",
    severity: "low",
    weight: 5,
    check: (val) => {
      if (!val) return { name: "Server Header", status: "pass", value: "Not disclosed", severity: "low", description: "Server software is not disclosed. Good for reducing information leakage.", remediation: "Properly configured." };
      const detailed = /\d+\.\d+/.test(val);
      if (detailed) return { name: "Server Header", status: "fail", value: val, severity: "low", description: "Server header exposes software version, aiding targeted attacks.", remediation: "Remove version information from the Server header or suppress it entirely." };
      return { name: "Server Header", status: "warn", value: val, severity: "low", description: "Server header reveals software type (but not version).", remediation: "Consider suppressing the Server header entirely." };
    },
  },
  {
    name: "X-Powered-By",
    key: "x-powered-by",
    severity: "low",
    weight: 5,
    check: (val) => {
      if (!val) return { name: "X-Powered-By", status: "pass", value: "Not disclosed", severity: "low", description: "Technology stack is not exposed via X-Powered-By.", remediation: "Properly configured." };
      return { name: "X-Powered-By", status: "fail", value: val, severity: "low", description: "X-Powered-By header exposes backend technology, helping attackers choose exploits.", remediation: "Remove the X-Powered-By header. In Express: `app.disable('x-powered-by')`." };
    },
  },
];

const TECH_SIGNATURES: { pattern: RegExp; name: string; category: string; source: "header" | "body" }[] = [
  { pattern: /nginx/i, name: "Nginx", category: "Web Server", source: "header" },
  { pattern: /apache/i, name: "Apache", category: "Web Server", source: "header" },
  { pattern: /cloudflare/i, name: "Cloudflare", category: "CDN", source: "header" },
  { pattern: /express/i, name: "Express.js", category: "Framework", source: "header" },
  { pattern: /asp\.net/i, name: "ASP.NET", category: "Framework", source: "header" },
  { pattern: /php/i, name: "PHP", category: "Language", source: "header" },
  { pattern: /next\.js/i, name: "Next.js", category: "Framework", source: "header" },
  { pattern: /wp-content|wordpress/i, name: "WordPress", category: "CMS", source: "body" },
  { pattern: /react/i, name: "React", category: "Frontend", source: "body" },
  { pattern: /__next/i, name: "Next.js", category: "Framework", source: "body" },
  { pattern: /vue/i, name: "Vue.js", category: "Frontend", source: "body" },
  { pattern: /angular/i, name: "Angular", category: "Frontend", source: "body" },
  { pattern: /jquery/i, name: "jQuery", category: "Library", source: "body" },
  { pattern: /bootstrap/i, name: "Bootstrap", category: "CSS Framework", source: "body" },
  { pattern: /tailwindcss|tailwind/i, name: "Tailwind CSS", category: "CSS Framework", source: "body" },
  { pattern: /google-analytics|gtag|GA-|G-/i, name: "Google Analytics", category: "Analytics", source: "body" },
  { pattern: /cloudflare/i, name: "Cloudflare", category: "CDN", source: "body" },
  { pattern: /akamai/i, name: "Akamai", category: "CDN", source: "header" },
  { pattern: /fastly/i, name: "Fastly", category: "CDN", source: "header" },
  { pattern: /vercel/i, name: "Vercel", category: "Hosting", source: "header" },
  { pattern: /netlify/i, name: "Netlify", category: "Hosting", source: "header" },
  { pattern: /heroku/i, name: "Heroku", category: "Hosting", source: "header" },
  { pattern: /drupal/i, name: "Drupal", category: "CMS", source: "body" },
  { pattern: /joomla/i, name: "Joomla", category: "CMS", source: "body" },
  { pattern: /shopify/i, name: "Shopify", category: "E-commerce", source: "body" },
  { pattern: /wix/i, name: "Wix", category: "Website Builder", source: "body" },
  { pattern: /squarespace/i, name: "Squarespace", category: "Website Builder", source: "body" },
  { pattern: /laravel/i, name: "Laravel", category: "Framework", source: "header" },
  { pattern: /django/i, name: "Django", category: "Framework", source: "header" },
  { pattern: /flask/i, name: "Flask", category: "Framework", source: "header" },
  { pattern: /ruby on rails|phusion/i, name: "Ruby on Rails", category: "Framework", source: "header" },
];

function parseCookies(setCookieHeaders: string[]): CookieResult[] {
  return setCookieHeaders.map((raw) => {
    const parts = raw.split(";").map((p) => p.trim());
    const nameVal = parts[0]?.split("=") || [];
    const name = nameVal[0] || "unknown";
    const lower = raw.toLowerCase();
    const httpOnly = lower.includes("httponly");
    const secure = lower.includes("secure");
    const sameSiteMatch = lower.match(/samesite=(strict|lax|none)/i);
    const sameSite = sameSiteMatch ? sameSiteMatch[1] : "Not set";
    const pathMatch = lower.match(/path=([^;]+)/i);
    const path = pathMatch ? pathMatch[1].trim() : "/";
    const issues: string[] = [];
    if (!httpOnly) issues.push("Missing HttpOnly flag — accessible to JavaScript (XSS risk)");
    if (!secure) issues.push("Missing Secure flag — cookie sent over unencrypted connections");
    if (sameSite === "Not set" || sameSite.toLowerCase() === "none") issues.push("Weak SameSite policy — vulnerable to CSRF attacks");
    return { name, httpOnly, secure, sameSite, path, issues };
  });
}

function detectTechnologies(headerStr: string, body: string): TechResult[] {
  const found = new Map<string, TechResult>();
  for (const sig of TECH_SIGNATURES) {
    const source = sig.source === "header" ? headerStr : body;
    if (sig.pattern.test(source) && !found.has(sig.name)) {
      const versionMatch = source.match(new RegExp(`${sig.name}[/\\s]+([\\d.]+)`, "i"));
      found.set(sig.name, { name: sig.name, category: sig.category, version: versionMatch?.[1], confidence: 90 });
    }
  }
  return Array.from(found.values());
}

export async function POST(req: NextRequest) {
  try {
    const parsed = await readUrlBodyAndGuard(req);
    if (parsed instanceof NextResponse) return parsed;
    const { url, hostname, raw: inputUrl } = parsed.target;
    const startTime = Date.now();

    if (!net.isIPv4(hostname) && !net.isIPv6(hostname)) {
      try {
        await dns.lookup(hostname);
      } catch {
        const body: UnreachableBody = {
          unreachable: true,
          code: "dns_failed",
          title: "Host not found",
          detail: `No working DNS for "${hostname}". The domain may be mistyped, expired, or not yet propagated.`,
          error: `DNS resolution failed for ${hostname}`,
        };
        return NextResponse.json(body, { status: 502 });
      }
    }

    let ip = "";
    try {
      const addresses = await dns.resolve4(hostname);
      ip = addresses[0] || "";
    } catch { /* ignore DNS failures for IP lookup (e.g. IPv6-only) */ }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    let response: Response;
    const redirectChain: string[] = [];
    try {
      response = await fetch(url, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: PRIMARY_SCAN_FETCH_HEADERS,
      });
    } catch (e: unknown) {
      clearTimeout(timeout);
      const { title, detail, error } = connectionFailureMessage(e);
      const body: UnreachableBody = {
        unreachable: true,
        code: "connection_failed",
        title,
        detail,
        error: `Failed to reach target: ${error}`,
      };
      return NextResponse.json(body, { status: 502 });
    }
    clearTimeout(timeout);

    const responseTime = Date.now() - startTime;
    const body = await response.text();

    if (response.redirected && response.url !== url) {
      redirectChain.push(url, response.url);
    }

    const headerMap: Record<string, string> = {};
    response.headers.forEach((value, key) => { headerMap[key.toLowerCase()] = value; });
    const headerStr = JSON.stringify(headerMap);

    const headerResults: HeaderResult[] = SECURITY_HEADERS.map((h) => h.check(headerMap[h.key] || null, headerMap));

    let score = 100;
    for (let i = 0; i < SECURITY_HEADERS.length; i++) {
      const r = headerResults[i];
      if (r.status === "fail") score -= SECURITY_HEADERS[i].weight;
      else if (r.status === "warn") score -= Math.floor(SECURITY_HEADERS[i].weight / 2);
    }
    score = Math.max(0, score);

    const setCookies = response.headers.getSetCookie?.() || [];
    const cookies = parseCookies(setCookies);
    if (cookies.some((c) => c.issues.length > 0)) score = Math.max(0, score - 5);

    const technologies = detectTechnologies(headerStr, body);

    const result: ScanResult = {
      target: { raw: inputUrl, url, hostname, ip },
      timestamp: new Date().toISOString(),
      score,
      grade: gradeFromScore(score),
      headers: headerResults,
      cookies,
      technologies,
      serverInfo: {
        server: headerMap["server"] || "Not disclosed",
        poweredBy: headerMap["x-powered-by"] || "Not disclosed",
        ip,
      },
      responseTime,
      statusCode: response.status,
      redirectChain,
    };

    return NextResponse.json(result);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
