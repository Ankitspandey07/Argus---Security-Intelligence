/**
 * AWS-focused checks: common misconfiguration URLs + extra pattern signals on responses.
 * Complements global secret patterns (e.g. AKIA…) in secret-patterns.ts.
 */

import type { SecretFinding } from "@/lib/source-scan";

const UA = "Argus-AwsLeakProbe/1.0 (by Ankit Pandey)";
const FETCH_TIMEOUT_MS = 9000;
const MAX_BODY = 120_000;

export type AwsProbeHit = {
  path: string;
  url: string;
  status: number;
  bodyChars: number;
  signal: "none" | "aws_signal" | "error";
  detail: string;
};

const PROBE_PATHS = [
  "/api/config",
  "/api/config.json",
  "/config.json",
  "/config.js",
  "/env.json",
  "/.env",
  "/env.js",
  "/aws.json",
  "/.aws/credentials",
  "/debug/config",
  "/server-info",
  "/metadata/instance",
];

/** Heuristic: looks like AWS-ish material without full secret matching. */
function classifyAwsishBody(text: string): { hit: boolean; detail: string } {
  const t = text.slice(0, 80_000);
  if (/\bAKIA[0-9A-Z]{16}\b/.test(t)) return { hit: true, detail: "Body contains AKIA-style access key material." };
  if (/\bASIA[0-9A-Z]{16}\b/.test(t)) return { hit: true, detail: "Body contains ASIA-style temporary key material." };
  if (/aws_secret_access_key|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|aws_session_token/i.test(t)) {
    return { hit: true, detail: "Body mentions AWS secret/session env-style strings." };
  }
  if (/amazonaws\.com[\/\w.\-]*\?.*[Xx]-[Aa]mz-[Cc]redential|[Aa]rn:aws:/i.test(t)) {
    return { hit: true, detail: "Body contains ARN or presigned-style AWS URL fragments." };
  }
  if (/"region"\s*:\s*"(?:us|eu|ap|ca|sa|me|af)-[a-z0-9-]+"/i.test(t) && /"(?:accessKeyId|secretAccessKey|sessionToken)"/i.test(t)) {
    return { hit: true, detail: "JSON looks like embedded AWS credential object shape." };
  }
  return { hit: false, detail: "" };
}

export async function probeAwsLeakyPaths(origin: string): Promise<AwsProbeHit[]> {
  const base = origin.replace(/\/$/, "");
  const out: AwsProbeHit[] = [];

  for (const path of PROBE_PATHS) {
    const url = `${base}${path}`;
    try {
      const res = await fetch(url, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        headers: { "User-Agent": UA, Accept: "application/json,text/plain,*/*" },
      });
      const buf = await res.arrayBuffer();
      const text = new TextDecoder("utf-8", { fatal: false }).decode(buf).slice(0, MAX_BODY);
      const bodyChars = text.length;

      if (!res.ok && bodyChars === 0) {
        out.push({
          path,
          url,
          status: res.status,
          bodyChars: 0,
          signal: "error",
          detail: "Empty or unreachable body.",
        });
        continue;
      }

      const { hit, detail } = classifyAwsishBody(text);
      out.push({
        path,
        url,
        status: res.status,
        bodyChars,
        signal: hit ? "aws_signal" : "none",
        detail: hit ? detail : `HTTP ${res.status}; no obvious AWS key patterns in first ${Math.min(bodyChars, MAX_BODY)} chars.`,
      });
    } catch (e: unknown) {
      out.push({
        path,
        url,
        status: 0,
        bodyChars: 0,
        signal: "error",
        detail: e instanceof Error ? e.message : "fetch failed",
      });
    }
  }

  return out;
}

export function filterAwsRelatedSecretFindings(findings: SecretFinding[]): SecretFinding[] {
  return findings.filter((f) => {
    if (f.patternId.startsWith("aws")) return true;
    if (/AWS|Amazon|AKIA|ASIA|arn:aws|x-amz|amazonaws/i.test(f.label)) return true;
    if (/AWS|Amazon|AKIA|ASIA|arn:aws|x-amz|amazonaws/i.test(f.hint)) return true;
    return false;
  });
}
