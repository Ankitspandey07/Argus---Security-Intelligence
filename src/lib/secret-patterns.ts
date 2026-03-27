/** High-signal patterns for exposed secrets in HTML/JS (server-side only). */

export interface SecretPattern {
  id: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  regex: RegExp;
  hint: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "aws_access_key",
    label: "AWS Access Key (AKIA…)",
    severity: "critical",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    hint: "Rotate in IAM immediately; never commit to client-side code.",
  },
  {
    id: "aws_temp_key",
    label: "AWS temporary key (ASIA…)",
    severity: "critical",
    regex: /\bASIA[0-9A-Z]{16}\b/g,
    hint: "STS-style key; revoke session and review CloudTrail for misuse.",
  },
  {
    id: "google_api_key",
    label: "Google API key (AIza…)",
    severity: "high",
    regex: /\bAIza[0-9A-Za-z\-_]{30,}\b/g,
    hint: "Restrict key by HTTP referrer / IP in Google Cloud Console.",
  },
  {
    id: "github_token",
    label: "GitHub token (ghp_/github_pat)",
    severity: "critical",
    regex: /\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{20,})\b/g,
    hint: "Revoke token; use short-lived fine-grained tokens only on server.",
  },
  {
    id: "slack_token",
    label: "Slack token",
    severity: "critical",
    regex: /\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b/g,
    hint: "Rotate Slack app credentials.",
  },
  {
    id: "stripe_live",
    label: "Stripe live secret",
    severity: "critical",
    regex: /\bsk_live_[0-9a-zA-Z]{20,}\b/g,
    hint: "Rotate in Stripe Dashboard immediately.",
  },
  {
    id: "stripe_test",
    label: "Stripe test secret",
    severity: "medium",
    regex: /\bsk_test_[0-9a-zA-Z]{20,}\b/g,
    hint: "Avoid shipping test keys; still indicates secret handling issues.",
  },
  {
    id: "openai_sk",
    label: "OpenAI-style API key (sk-…)",
    severity: "critical",
    regex: /\bsk-[a-zA-Z0-9]{32,}\b/g,
    hint: "Revoke key; proxy AI calls server-side only.",
  },
  {
    id: "generic_api_assignment",
    label: "Possible API key assignment",
    severity: "medium",
    regex: /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*["']([a-zA-Z0-9_\-.]{16,})["']/gi,
    hint: "Review manually; move secrets to environment / vault.",
  },
  {
    id: "private_key_block",
    label: "Private key block",
    severity: "critical",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    hint: "Rotate certificate/key material; never embed in web assets.",
  },
  {
    id: "jwt_bearer",
    label: "JWT-like bearer (eyJ…)",
    severity: "low",
    regex: /\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g,
    hint: "Decode to inspect claims; verify signature server-side only.",
  },
  {
    id: "firebase",
    label: "Firebase / generic URL with embedded key",
    severity: "medium",
    regex: /firebaseio\.com.*[?&]key=[a-zA-Z0-9_-]{20,}/gi,
    hint: "Lock down Firebase rules; API keys in URLs are often abusable.",
  },
  {
    id: "mongodb_uri",
    label: "MongoDB connection string",
    severity: "critical",
    regex: /mongodb(\+srv)?:\/\/[^\s"'<>]+/gi,
    hint: "Rotate credentials; never expose connection strings client-side.",
  },
  {
    id: "postgres_uri",
    label: "PostgreSQL / MySQL URI",
    severity: "critical",
    regex: /(?:postgres|postgresql|mysql):\/\/[^\s"'<>]+/gi,
    hint: "Rotate DB password; use secrets manager.",
  },
];

export function redactMatch(raw: string, keepStart = 4, keepEnd = 2): string {
  if (raw.length <= keepStart + keepEnd + 3) return "***";
  return `${raw.slice(0, keepStart)}…${raw.slice(-keepEnd)}`;
}
