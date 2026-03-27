/**
 * Heuristic analysis of VirusTotal v2 domain/report style payloads for Argus UI + PDF.
 */

export interface VirusTotalConcern {
  id: string;
  title: string;
  detail: string;
  severity: "info" | "low" | "medium" | "high";
}

export interface VirusTotalNovice {
  /** Simple traffic-light level for UI */
  level: "green" | "amber" | "red";
  title: string;
  /** One short sentence */
  subtitle: string;
  /** 2–4 sentences, no jargon */
  explanation: string;
  /** Plain-language bullets (max 4) */
  bullets: string[];
  /** Single actionable line */
  whatNow: string;
}

export interface VirusTotalAnalysis {
  verdict: "clean" | "caution" | "concerning";
  headline: string;
  summaryPlain: string;
  concerns: VirusTotalConcern[];
  novice: VirusTotalNovice;
  stats: {
    detectedUrlsSampled: number;
    urlsWithPositives: number;
    maxPositivesOnUrl: number;
    communicatingSamples: number;
    communicatingWithPositives: number;
    downloadedSamples: number;
    downloadedWithPositives: number;
    subdomainCountListed: number;
  };
}

function num(v: unknown): number {
  return typeof v === "number" && !Number.isNaN(v) ? v : 0;
}

/** Analyze normalized VT response fields (already extracted in API route). */
export function analyzeVirusTotalDomainReport(input: {
  categories?: unknown;
  detectedUrls?: unknown[];
  detectedCommunicatingSamples?: unknown[];
  detectedDownloadedSamples?: unknown[];
  subdomains?: unknown[];
  whois?: string | undefined;
}): VirusTotalAnalysis {
  const detectedUrls = Array.isArray(input.detectedUrls) ? input.detectedUrls : [];
  const communicating = Array.isArray(input.detectedCommunicatingSamples)
    ? input.detectedCommunicatingSamples
    : [];
  const downloaded = Array.isArray(input.detectedDownloadedSamples) ? input.detectedDownloadedSamples : [];
  const subs = Array.isArray(input.subdomains) ? input.subdomains : [];

  let urlsWithPositives = 0;
  let maxPositivesOnUrl = 0;
  for (const u of detectedUrls) {
    const o = u as { positives?: number; total?: number; url?: string };
    const p = num(o.positives);
    if (p > 0) urlsWithPositives++;
    if (p > maxPositivesOnUrl) maxPositivesOnUrl = p;
  }

  let commWithPos = 0;
  for (const s of communicating) {
    const o = s as { positives?: number };
    if (num(o.positives) > 0) commWithPos++;
  }

  let downWithPos = 0;
  for (const s of downloaded) {
    const o = s as { positives?: number };
    if (num(o.positives) > 0) downWithPos++;
  }

  const concerns: VirusTotalConcern[] = [];
  const catStr = JSON.stringify(input.categories || {}).toLowerCase();

  if (catStr.includes("malicious") || catStr.includes("phishing") || catStr.includes("malware")) {
    concerns.push({
      id: "cat",
      title: "Reputation category flags",
      detail: `VirusTotal associates one or more vendor categories with this domain that suggest abuse or risk. Review the category list and your relationship to this domain.`,
      severity: "high",
    });
  }

  if (urlsWithPositives > 0 && (maxPositivesOnUrl >= 2 || urlsWithPositives <= 5)) {
    concerns.push({
      id: "urls",
      title: "Some archived URLs were flagged by antivirus engines",
      detail: `VirusTotal keeps a history of URLs on this domain. ${urlsWithPositives} sample URL(s) had at least one detection (strongest single URL: ${maxPositivesOnUrl} engine hits). Popular sites often show old or third-party path flags — treat as a hygiene check, not automatic proof of hacking.`,
      severity: maxPositivesOnUrl >= 8 ? "high" : maxPositivesOnUrl >= 3 ? "medium" : "low",
    });
  } else if (urlsWithPositives > 5 && maxPositivesOnUrl <= 1) {
    concerns.push({
      id: "urls_noise",
      title: "Lots of tiny URL flags (often normal for big sites)",
      detail: `Many historical URLs show only 1 engine positive each — common for large properties and CDNs. Focus on your own subdomains and any category or sample issues below.`,
      severity: "low",
    });
  }

  let commStrong = 0;
  for (const s of communicating) {
    const o = s as { positives?: number; total?: number };
    const p = num(o.positives);
    const t = Math.max(num(o.total), 1);
    if (p >= 4 || p / t >= 0.2) commStrong++;
  }

  const badCategory =
    catStr.includes("malicious") || catStr.includes("phishing") || catStr.includes("malware");
  const largeDnsFootprint = subs.length >= 35;
  const urlPathSignal = urlsWithPositives > 0 && maxPositivesOnUrl >= 2;

  if (commStrong >= 1 || commWithPos >= 8) {
    let severity: VirusTotalConcern["severity"] = "medium";
    let title = "Malware samples linked to this domain";
    let detail = `${commWithPos} VT sample(s) list this hostname; ${commStrong} had stronger multi-engine ratios. Cross-check in VirusTotal GUI + your DNS/CDN inventory.`;

    if (badCategory || urlPathSignal) {
      severity = commStrong >= 4 ? "high" : "medium";
    } else if (largeDnsFootprint && detectedUrls.length === 0) {
      severity = "info";
      title = "Historical samples + large subdomain index (context)";
      detail =
        "Typical for major brands: many historical files once communicated with infrastructure in this DNS space. Open the full JSON export below or VT GUI to verify — not treated as a standalone red flag here.";
    } else {
      severity = commStrong >= 6 ? "high" : commStrong >= 3 ? "medium" : "low";
    }

    concerns.push({ id: "comm", title, detail, severity });
  }

  if (downWithPos > 0) {
    concerns.push({
      id: "dl",
      title: "Malware samples referencing downloads",
      detail: `${downWithPos} downloaded sample(s) linked to this domain received positive detections. Check historical hosting of executables or archives.`,
      severity: "medium",
    });
  }

  if (subs.length > 80) {
    concerns.push({
      id: "subs",
      title: "Large subdomain surface in VirusTotal index",
      detail: `VirusTotal lists ${subs.length}+ subdomains. A broad DNS footprint increases takeover and phishing surface — align with your internal inventory.`,
      severity: "low",
    });
  }

  const whois = input.whois || "";
  if (/password|passwd|credential|BEGIN RSA PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY/i.test(whois)) {
    concerns.push({
      id: "whois",
      title: "WHOIS text may contain sensitive-looking strings",
      detail:
        "The WHOIS snippet includes text that resembles credentials or key material (often false positives from registrar templates). Expand raw WHOIS in VirusTotal only on authorized assessments — do not exfiltrate secrets.",
      severity: "medium",
    });
  }

  const forVerdict = concerns.filter((c) => c.severity !== "info");
  let verdict: VirusTotalAnalysis["verdict"] = "clean";
  if (forVerdict.some((c) => c.severity === "high")) verdict = "concerning";
  else if (
    forVerdict.some((c) => c.severity === "medium") ||
    forVerdict.filter((c) => c.severity === "low").length >= 2
  ) {
    verdict = "caution";
  }

  const headline =
    verdict === "clean"
      ? "No elevated risk verdict from our rules on this snapshot (see full export for raw VT data)."
      : verdict === "caution"
        ? "Some VirusTotal fields merit a human glance — details below."
        : "Stronger combined signals — validate in VirusTotal before high-risk decisions.";

  const summaryPlain = [
    `Automated read of VirusTotal domain intelligence (sampled URLs, samples, categories).`,
    verdict === "clean"
      ? `No high-severity items after filtering contextual noise. Expand “Full VT export” JSON for manual verification anytime.`
      : `We flagged ${forVerdict.length} item(s) above informational noise — review with your team and the raw export.`,
    `Use VirusTotal only per their Terms of Service and for authorized targets.`,
  ].join(" ");

  const concernToPlain = (c: VirusTotalConcern): string => {
    const one = c.detail.split(". ")[0];
    if (c.id === "cat") return "VirusTotal vendors tagged this domain with a sensitive category (for example malware or phishing).";
    if (c.id === "urls") return one.endsWith(".") ? one : `${one}.`;
    if (c.id === "urls_noise") return "Many old URLs have single-engine hits — typical noise for huge sites; still skim if this is your brand.";
    if (c.id === "comm") return "Some malware files in VirusTotal's database once talked to this domain — make sure that matches how you use DNS.";
    if (c.id === "dl") return "A few downloaded files tied to this domain were flagged — check if you ever hosted installers or archives here.";
    if (c.id === "subs") return "VirusTotal knows about many subdomains — keep your own DNS inventory tidy to reduce takeover risk.";
    if (c.id === "whois") return "WHOIS text triggered a sensitive-keyword check — usually registrar boilerplate, not a real leak.";
    return one;
  };

  const bullets = forVerdict.slice(0, 4).map(concernToPlain);
  const novice: VirusTotalNovice =
    verdict === "clean"
      ? {
          level: "green",
          title: "Looks calm in this snapshot",
          subtitle: "We did not see high-priority combinations in the data we sampled.",
          explanation:
            "VirusTotal is a crowd-sourced history service, not a guarantee. Green here means our automatic rules did not find strong category flags plus heavy sample signals. If this domain is yours, you should still follow normal patching and monitoring.",
          bullets: bullets.length ? bullets : ["No major automated alerts in this view."],
          whatNow: "Keep using good security basics (HTTPS, MFA, logging). Re-scan after major infrastructure changes.",
        }
      : verdict === "caution"
        ? {
            level: "amber",
            title: "Worth a quick human look",
            subtitle: "There are notes in the history — usually fine for big brands, double-check for small sites.",
            explanation:
              "VirusTotal stores years of URL and file relationships. Amber means we saw something interesting but not an automatic 'emergency'. If you recognize every hostname and service, you can often file this as informational.",
            bullets: bullets.length ? bullets : ["Review the bullets below with someone who knows your hosting setup."],
            whatNow: "Open “Technical details” only if you need evidence, and only on domains you are allowed to test.",
          }
        : {
            level: "red",
            title: "Treat as higher priority",
            subtitle: "Several stronger signals showed up together — validate before trusting this domain for sensitive work.",
            explanation:
              "Red means our rules saw high-severity items (for example dangerous vendor categories or strong sample detections). It still needs human confirmation, but you should loop in security or IT soon.",
            bullets: bullets.length ? bullets : ["Review VirusTotal with your security team."],
            whatNow: "Confirm DNS and cloud ownership, check recent incidents, and avoid using this hostname for new critical flows until reviewed.",
          };

  return {
    verdict,
    headline,
    summaryPlain,
    concerns,
    novice,
    stats: {
      detectedUrlsSampled: detectedUrls.length,
      urlsWithPositives,
      maxPositivesOnUrl,
      communicatingSamples: communicating.length,
      communicatingWithPositives: commWithPos,
      downloadedSamples: downloaded.length,
      downloadedWithPositives: downWithPos,
      subdomainCountListed: subs.length,
    },
  };
}
