import { NextResponse } from "next/server";
import { normalizeTarget } from "@/lib/utils";
import { isBlockedShortenHostname } from "@/lib/url-safety";

/**
 * Block SSRF-style targets for scanner modules (outbound fetch / TLS / DNS to user-supplied host).
 * Reuses private-range logic from url-safety; adds cloud metadata hostnames.
 * Set ARGUS_ALLOW_PRIVATE_TARGETS=1 to disable blocking (lab only).
 */

export function isBlockedScanHostname(hostname: string): boolean {
  const h = hostname.trim().toLowerCase().replace(/\.$/, "");
  if (!h) return true;
  if (isBlockedShortenHostname(h)) return true;
  if (h === "metadata.google.internal" || h.endsWith(".metadata.google.internal")) return true;
  if (h === "metadata" || h === "instance-data") return true;
  return false;
}

function allowPrivateTargets(): boolean {
  return process.env.ARGUS_ALLOW_PRIVATE_TARGETS === "1" || process.env.ARGUS_ALLOW_PRIVATE_TARGETS === "true";
}

/**
 * If ARGUS_ALLOWED_DOMAINS is set (comma-separated), hostname must equal a rule or be a subdomain of it.
 * Rules: `example.com` allows `foo.example.com` and `example.com`.
 * A leading dot means suffix-only: `.corp.internal` matches `x.corp.internal`.
 */
export function assertDomainAllowlist(hostname: string): NextResponse | null {
  const raw = process.env.ARGUS_ALLOWED_DOMAINS?.trim();
  if (!raw) return null;
  const rules = raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (rules.length === 0) return null;

  const h = hostname.toLowerCase().replace(/\.$/, "");
  const ok = rules.some((rule) => {
    if (rule.startsWith(".")) {
      const suf = rule.slice(1);
      return h === suf || h.endsWith("." + suf);
    }
    return h === rule || h.endsWith("." + rule);
  });

  if (!ok) {
    return NextResponse.json(
      {
        error:
          "Target hostname is not on the server allowlist (ARGUS_ALLOWED_DOMAINS). Contact your Argus administrator.",
      },
      { status: 403 },
    );
  }
  return null;
}

export type ParsedScanTarget = { hostname: string; url: string; raw: string };

/** Parse and validate primary scan URL; returns NextResponse on error. */
export function parseScanTargetOrError(rawInput: string): ParsedScanTarget | NextResponse {
  const raw = rawInput.trim();
  if (!raw) {
    return NextResponse.json({ error: "URL is required" }, { status: 400 });
  }

  const { url, hostname } = normalizeTarget(raw);
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return NextResponse.json({ error: "Only http and https targets are allowed" }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ error: "Invalid URL" }, { status: 400 });
  }

  if (!allowPrivateTargets() && isBlockedScanHostname(hostname)) {
    return NextResponse.json(
      {
        error:
          "Target is blocked (private/local/link-local/metadata-style host). For lab scans set ARGUS_ALLOW_PRIVATE_TARGETS=1 (not for public deployments).",
      },
      { status: 403 },
    );
  }

  const allow = assertDomainAllowlist(hostname);
  if (allow) return allow;

  return { hostname, url, raw };
}

/** Validate bare hostname (takeover list, etc.). */
export function parseHostnameOrError(host: string): { hostname: string } | NextResponse {
  const h = host
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .replace(/\.$/, "");
  if (!h) {
    return NextResponse.json({ error: "Invalid host" }, { status: 400 });
  }
  if (!allowPrivateTargets() && isBlockedScanHostname(h)) {
    return NextResponse.json({ error: "Host is blocked (private/local/metadata ranges)." }, { status: 403 });
  }
  const allow = assertDomainAllowlist(h);
  if (allow) return allow;
  return { hostname: h };
}
