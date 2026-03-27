import { NextRequest, NextResponse } from "next/server";
import { guardArgusRequest } from "@/lib/api-guard";
import { parseScanTargetOrError } from "@/lib/scan-target-policy";
import { argusAudit } from "@/lib/argus-audit";
import { getSslCached, setSslCached } from "@/lib/ssl-result-cache";
import tls from "tls";
import type { SSLResult } from "@/lib/types";
import { assessNegotiatedCipher } from "@/lib/ssl-cipher";
import { analyzeTlsProbeContext } from "@/lib/ssl-probe-context";

function connectTLS(hostname: string, port = 443): Promise<{
  cert: tls.PeerCertificate;
  protocol: string | null;
  cipher: tls.CipherNameAndProtocol | null;
  authorized: boolean;
}> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;
      socket.end();
      resolve({ cert, protocol, cipher, authorized });
    });
    socket.setTimeout(10000);
    socket.on("timeout", () => { socket.destroy(); reject(new Error("TLS connection timed out")); });
    socket.on("error", reject);
  });
}

function parseCertDate(raw: string): string {
  try { return new Date(raw).toISOString(); }
  catch { return raw; }
}

export async function POST(req: NextRequest) {
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const body = await req.json().catch(() => null);
    const inputUrl = body?.url;
    if (typeof inputUrl !== "string" || !inputUrl.trim()) {
      return NextResponse.json({ error: "URL/hostname is required" }, { status: 400 });
    }
    const target = parseScanTargetOrError(inputUrl);
    if (target instanceof NextResponse) return target;
    const { hostname } = target;
    argusAudit("ssl_probe", { hostname });

    const cached = getSslCached(hostname);
    if (cached) return NextResponse.json({ ...cached, cached: true });

    const { cert, protocol, cipher, authorized } = await connectTLS(hostname);

    const validFrom = parseCertDate(cert.valid_from);
    const validTo = parseCertDate(cert.valid_to);
    const daysUntilExpiry = Math.floor((new Date(validTo).getTime() - Date.now()) / 86400000);

    const issuer: string = typeof cert.issuer === "object"
      ? String(cert.issuer.O || cert.issuer.CN || JSON.stringify(cert.issuer))
      : String(cert.issuer || "Unknown");

    const subject: string = typeof cert.subject === "object"
      ? String(cert.subject.CN || JSON.stringify(cert.subject))
      : String(cert.subject || "Unknown");

    const keyBits = cert.bits || 0;
    const certAny = cert as unknown as Record<string, unknown>;
    const sigAlg = (certAny.sigalg as string) ||
      (certAny.signatureAlgorithm as string) || "Unknown";

    const protocols: { name: string; supported: boolean }[] = [];
    for (const proto of ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]) {
      try {
        await new Promise<void>((resolve, reject) => {
          const s = tls.connect({
            host: hostname, port: 443, servername: hostname,
            rejectUnauthorized: false,
            minVersion: proto as tls.SecureVersion,
            maxVersion: proto as tls.SecureVersion,
          }, () => { s.end(); resolve(); });
          s.setTimeout(5000);
          s.on("timeout", () => { s.destroy(); reject(); });
          s.on("error", reject);
        });
        protocols.push({ name: proto, supported: true });
      } catch {
        protocols.push({ name: proto, supported: false });
      }
    }

    const vulnerabilities: SSLResult["vulnerabilities"] = [];
    if (protocols.find(p => p.name === "TLSv1" && p.supported)) {
      vulnerabilities.push({ name: "TLS 1.0 Supported", vulnerable: true, description: "TLS 1.0 is deprecated and has known vulnerabilities (BEAST, POODLE)." });
    }
    if (protocols.find(p => p.name === "TLSv1.1" && p.supported)) {
      vulnerabilities.push({ name: "TLS 1.1 Supported", vulnerable: true, description: "TLS 1.1 is deprecated. Most browsers have removed support." });
    }
    if (!protocols.find(p => p.name === "TLSv1.3" && p.supported)) {
      vulnerabilities.push({ name: "TLS 1.3 Not Supported", vulnerable: true, description: "TLS 1.3 provides significant security and performance improvements." });
    }
    if (daysUntilExpiry <= 30) {
      vulnerabilities.push({ name: "Certificate Expiring Soon", vulnerable: true, description: `Certificate expires in ${daysUntilExpiry} days.` });
    }
    if (daysUntilExpiry < 0) {
      vulnerabilities.push({ name: "Certificate Expired", vulnerable: true, description: "The SSL certificate has expired." });
    }
    if (!authorized) {
      vulnerabilities.push({ name: "Certificate Not Trusted", vulnerable: true, description: "The certificate chain is not trusted by the system." });
    }
    if (keyBits > 0 && keyBits < 2048) {
      vulnerabilities.push({ name: "Weak Key Size", vulnerable: true, description: `Key size is ${keyBits} bits. 2048+ is recommended.` });
    }

    const certChain: { subject: string; issuer: string }[] = [];
    let current: tls.PeerCertificate | undefined = cert;
    const seen = new Set<string>();
    while (current && !seen.has(current.fingerprint256 || "")) {
      seen.add(current.fingerprint256 || "");
      const s = typeof current.subject === "object" ? String(current.subject.CN || "") : "";
      const i = typeof current.issuer === "object" ? String(current.issuer.CN || current.issuer.O || "") : "";
      certChain.push({ subject: s, issuer: i });
      current = (current as unknown as { issuerCertificate?: tls.PeerCertificate }).issuerCertificate;
    }

    const cipherName = cipher?.name && cipher?.version
      ? { name: cipher.name, version: cipher.version }
      : cipher?.name
        ? { name: cipher.name, version: cipher.version || "" }
        : null;
    const cipherAssessment = assessNegotiatedCipher(cipherName);

    const cipherIssues = cipherAssessment.issues;
    if (cipherAssessment.strength === "weak") {
      vulnerabilities.push({
        name: "Weak TLS cipher suite",
        vulnerable: true,
        description: `Negotiated cipher "${cipherAssessment.negotiated?.name || "unknown"}" matches legacy or broken primitives. Prefer TLS 1.3 or ECDHE + AEAD.`,
      });
    } else if (cipherAssessment.strength === "acceptable" && cipherIssues.length > 0) {
      vulnerabilities.push({
        name: "Cipher suite review",
        vulnerable: false,
        description: `Negotiated "${cipherAssessment.negotiated?.name || ""}" — ${cipherIssues[0]?.title || "legacy patterns"}; consider modern ECDHE + AES-GCM.`,
      });
    }

    const probeContext = analyzeTlsProbeContext(issuer, certChain);
    if (probeContext.likelyCorporateTlsInspection) {
      vulnerabilities.push({
        name: "TLS inspection / proxy certificate (informational)",
        vulnerable: false,
        description:
          "Issuer or chain matches a known SSL-inspection / forward-proxy pattern. The grade and expiry below may describe the proxy's certificate, not the origin's public TLS on the open Internet.",
      });
    }

    /** Proxy certs often expire on short cycles; don't penalize letter grade for that alone when inspection is detected */
    const gradeRelevant = vulnerabilities.filter((v) => {
      if (!v.vulnerable) return false;
      if (probeContext.likelyCorporateTlsInspection && v.name === "Certificate Expiring Soon") return false;
      return true;
    });
    let grade = "A";
    const vulnCount = gradeRelevant.length;
    if (vulnCount >= 3) grade = "F";
    else if (vulnCount === 2) grade = "C";
    else if (vulnCount === 1) grade = "B";

    const result: SSLResult = {
      grade,
      protocol: protocol || "Unknown",
      issuer, subject,
      validFrom, validTo, daysUntilExpiry,
      keySize: keyBits,
      signatureAlgorithm: sigAlg,
      protocols, vulnerabilities, certChain,
      negotiatedCipher: cipherAssessment.negotiated,
      cipherStrength: cipherAssessment.strength,
      cipherIssues: cipherAssessment.issues,
      probeContext: probeContext.likelyCorporateTlsInspection ? probeContext : undefined,
    };

    setSslCached(hostname, result);
    return NextResponse.json(result);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "SSL analysis failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
