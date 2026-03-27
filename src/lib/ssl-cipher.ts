/**
 * Heuristic classification of TLS cipher suite names (negotiated cipher from Node tls.getCipher()).
 */

export interface CipherAssessment {
  negotiated: { name: string; version: string } | null;
  strength: "strong" | "acceptable" | "weak";
  issues: { title: string; description: string }[];
}

const WEAK_SUBSTRINGS = [
  { s: "NULL", title: "NULL cipher", description: "NULL encryption offers no confidentiality." },
  { s: "EXPORT", title: "EXPORT-grade cipher", description: "Historically weak export ciphers are unsafe." },
  { s: "_DES_", title: "DES-based cipher", description: "DES/3DES variants are deprecated for TLS in modern baselines." },
  { s: "DES-CBC", title: "DES/CBC cipher", description: "Legacy block cipher — prefer AES-GCM or ChaCha20-Poly1305." },
  { s: "RC4", title: "RC4 stream cipher", description: "RC4 is broken and must not be used." },
  { s: "_MD5", title: "MD5 in cipher suite", description: "MD5 for TLS integrity is considered weak." },
  { s: "anon", title: "Anonymous key exchange", description: "Anonymous DH/ECDH provides no server authentication." },
  { s: "ADH", title: "Anonymous DH", description: "Cipher suites without server authentication." },
  { s: "AECDH", title: "Anonymous ECDH", description: "Anonymous elliptic-curve DH — no certificate authentication." },
];

/** CBC with TLS 1.2-only classical RSA key exchange patterns — informational */
const CBC_INFO = /WITH_AES_(128|256)_CBC_SHA(256)?$/;

export function assessNegotiatedCipher(cipher: { name: string; version: string } | null | undefined): CipherAssessment {
  const issues: { title: string; description: string }[] = [];
  if (!cipher?.name) {
    return {
      negotiated: null,
      strength: "acceptable",
      issues: [{ title: "Cipher not reported", description: "Could not read negotiated cipher from the TLS socket." }],
    };
  }

  const upper = cipher.name.toUpperCase();

  for (const w of WEAK_SUBSTRINGS) {
    if (upper.includes(w.s.toUpperCase())) {
      issues.push({ title: w.title, description: w.description });
    }
  }

  if (CBC_INFO.test(upper) && upper.includes("TLS_RSA")) {
    issues.push({
      title: "Legacy RSA key transport + CBC",
      description: "Prefer TLS 1.3 or ECDHE with AEAD (AES-GCM / CHACHA20). RSA key transport and CBC are legacy patterns.",
    });
  }

  let strength: CipherAssessment["strength"] = "strong";
  if (issues.some((i) => i.title.includes("RC4") || i.title.includes("NULL") || i.title.includes("EXPORT") || i.title.includes("Anonymous"))) {
    strength = "weak";
  } else if (issues.length > 0) {
    strength = "acceptable";
  }

  return {
    negotiated: { name: cipher.name, version: cipher.version },
    strength,
    issues,
  };
}
