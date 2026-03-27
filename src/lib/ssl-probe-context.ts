/**
 * Detects when TLS metadata likely reflects a corporate SSL inspection proxy
 * (Zscaler, Netskope, etc.) rather than the origin server's public certificate chain.
 */

const INSPECTION_MARKERS: { test: RegExp; label: string }[] = [
  { test: /zscaler/i, label: "Zscaler" },
  { test: /netskope/i, label: "Netskope" },
  { test: /palo\s*alto/i, label: "Palo Alto Networks" },
  { test: /barracuda/i, label: "Barracuda" },
  { test: /forcepoint/i, label: "Forcepoint" },
  { test: /sophos/i, label: "Sophos" },
  { test: /fortinet/i, label: "Fortinet" },
  { test: /blue\s*coat/i, label: "Blue Coat / Symantec proxy" },
  { test: /cisco\s*umbrella/i, label: "Cisco Umbrella" },
  { test: /checkpoint/i, label: "Check Point" },
  { test: /mimecast/i, label: "Mimecast" },
  { test: /ssl\s*inspection/i, label: "SSL inspection (generic)" },
  { test: /decrypt/i, label: "TLS decryption (generic)" },
];

export type TlsProbeContext = {
  /** True when issuer/chain suggests outbound TLS was intercepted by a gateway */
  likelyCorporateTlsInspection: boolean;
  /** Human-readable guidance for the UI / PDF */
  notes: string[];
};

export function analyzeTlsProbeContext(
  issuer: string,
  certChain: { subject: string; issuer: string }[],
): TlsProbeContext {
  const haystack = [issuer, ...certChain.flatMap((c) => [c.subject, c.issuer])].join(" | ");
  const matched = new Set<string>();
  for (const { test, label } of INSPECTION_MARKERS) {
    if (test.test(haystack)) matched.add(label);
  }
  const likelyCorporateTlsInspection = matched.size > 0;
  const notes: string[] = [];
  if (likelyCorporateTlsInspection) {
    notes.push(
      `TLS inspection / forward-proxy likely (${[...matched].slice(0, 4).join(", ")}). Argus is showing the certificate presented to this scanner's environment, which may differ from what the public Internet sees for the same hostname.`,
    );
    notes.push(
      "If you need the site's real public chain and grade, run a scan from a host without SSL inspection (e.g. cloud VPS, CI) or compare with SSL Labs / testssl.sh from a clean network.",
    );
  }
  return { likelyCorporateTlsInspection, notes };
}
