/**
 * Subdomain takeover heuristics: CNAME targets that often indicate dangling records.
 * Inspired by public takeover lists; HTTP checks are best-effort.
 */

export interface TakeoverFingerprint {
  service: string;
  cnameSuffix: string;
  /** Substrings in body that suggest unclaimed / misconfigured */
  unclaimedMarkers: RegExp[];
  severity: "high" | "medium";
}

export const TAKEOVER_FINGERPRINTS: TakeoverFingerprint[] = [
  {
    service: "GitHub Pages",
    cnameSuffix: "github.io",
    unclaimedMarkers: [/There isn't a GitHub Pages site here/i, /For root URLs/i],
    severity: "high",
  },
  {
    service: "Heroku",
    cnameSuffix: "herokuapp.com",
    unclaimedMarkers: [/no such app/i, /herokucdn.com error/i],
    severity: "high",
  },
  {
    service: "Azure",
    cnameSuffix: "azurewebsites.net",
    unclaimedMarkers: [/404 Web Site not found/i, /Error 404/i],
    severity: "medium",
  },
  {
    service: "AWS S3 website",
    cnameSuffix: "s3-website",
    unclaimedMarkers: [/NoSuchBucket/i, /The specified bucket does not exist/i],
    severity: "high",
  },
  {
    service: "AWS S3",
    cnameSuffix: ".s3.amazonaws.com",
    unclaimedMarkers: [/NoSuchBucket/i, /The specified bucket does not exist/i],
    severity: "high",
  },
  {
    service: "Shopify",
    cnameSuffix: "myshopify.com",
    unclaimedMarkers: [/Sorry, this shop is currently unavailable/i],
    severity: "medium",
  },
  {
    service: "Fastly",
    cnameSuffix: "fastly.net",
    unclaimedMarkers: [/Fastly error: unknown domain/i],
    severity: "medium",
  },
  {
    service: "Zendesk",
    cnameSuffix: "zendesk.com",
    unclaimedMarkers: [/Help Center Closed/i, /doesn't exist/i],
    severity: "medium",
  },
  {
    service: "Netlify",
    cnameSuffix: "netlify.app",
    unclaimedMarkers: [/Not Found - Request ID:/i, /Page not found/i],
    severity: "high",
  },
  {
    service: "Netlify (legacy)",
    cnameSuffix: "netlify.com",
    unclaimedMarkers: [/Not Found - Request ID:/i],
    severity: "medium",
  },
  {
    service: "Vercel",
    cnameSuffix: "vercel.app",
    unclaimedMarkers: [/DEPLOYMENT_NOT_FOUND/i, /The deployment could not be found/i],
    severity: "high",
  },
  {
    service: "CloudFront",
    cnameSuffix: "cloudfront.net",
    unclaimedMarkers: [/The request could not be satisfied/i, /Bad request\. We can't connect to the server/i],
    severity: "medium",
  },
  {
    service: "Readthedocs",
    cnameSuffix: "readthedocs.io",
    unclaimedMarkers: [/Unknown Project/i, /isn't one of Read the Docs' subdomains/i],
    severity: "medium",
  },
  {
    service: "Ghost",
    cnameSuffix: "ghost.io",
    unclaimedMarkers: [/Domain is not configured/i],
    severity: "medium",
  },
  {
    service: "Surge.sh",
    cnameSuffix: "surge.sh",
    unclaimedMarkers: [/project not found/i],
    severity: "high",
  },
  {
    service: "Pantheon",
    cnameSuffix: "pantheonsite.io",
    unclaimedMarkers: [/404 error unknown site!/i],
    severity: "medium",
  },
  {
    service: "Tumblr",
    cnameSuffix: "tumblr.com",
    unclaimedMarkers: [/Whatever you were looking for doesn't currently exist/i],
    severity: "medium",
  },
  {
    service: "Bitbucket",
    cnameSuffix: "bitbucket.io",
    unclaimedMarkers: [/Repository not found/i],
    severity: "high",
  },
  {
    service: "Google Cloud Storage",
    cnameSuffix: "storage.googleapis.com",
    unclaimedMarkers: [
      /<Code>NoSuchBucket<\/Code>/i,
      /The specified bucket does not exist/i,
    ],
    severity: "high",
  },
];

export function findFingerprintForCname(cname: string): TakeoverFingerprint | null {
  const lower = cname.toLowerCase().replace(/\.$/, "");
  for (const fp of TAKEOVER_FINGERPRINTS) {
    if (lower.endsWith(fp.cnameSuffix) || lower.includes(fp.cnameSuffix)) return fp;
  }
  return null;
}
