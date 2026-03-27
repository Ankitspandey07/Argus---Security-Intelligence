export interface ScanTarget {
  raw: string;
  url: string;
  hostname: string;
  ip?: string;
}

export interface HeaderResult {
  name: string;
  status: "pass" | "fail" | "warn";
  value: string;
  description: string;
  remediation: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
}

export interface ScanResult {
  target: ScanTarget;
  timestamp: string;
  score: number;
  grade: string;
  headers: HeaderResult[];
  cookies: CookieResult[];
  technologies: TechResult[];
  serverInfo: { server: string; poweredBy: string; ip: string };
  responseTime: number;
  statusCode: number;
  redirectChain: string[];
}

export interface CookieResult {
  name: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string;
  path: string;
  issues: string[];
}

export interface TechResult {
  name: string;
  category: string;
  version?: string;
  confidence: number;
}

export interface SSLResult {
  grade: string;
  protocol: string;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  keySize: number;
  signatureAlgorithm: string;
  protocols: { name: string; supported: boolean }[];
  vulnerabilities: { name: string; vulnerable: boolean; description: string }[];
  certChain: { subject: string; issuer: string }[];
  /** Negotiated cipher on the probe connection */
  negotiatedCipher?: { name: string; version: string } | null;
  cipherStrength?: "strong" | "acceptable" | "weak";
  cipherIssues?: { title: string; description: string }[];
  /** Present when the certificate chain suggests corporate TLS inspection (e.g. Zscaler) */
  probeContext?: {
    likelyCorporateTlsInspection: boolean;
    notes: string[];
  };
}

export interface DNSRecord {
  type: string;
  value: string;
  ttl?: number;
  priority?: number;
}

export interface DNSResult {
  records: DNSRecord[];
  hasDNSSEC: boolean;
  nameservers: string[];
  mailServers: string[];
}

export interface SubdomainResult {
  subdomain: string;
  source: string;
  firstSeen?: string;
}

export interface PortResult {
  port: number;
  service: string;
  product?: string;
  version?: string;
  cpes: string[];
  vulns: string[];
  exposureRisk?: "critical" | "high" | "medium";
  exposureReason?: string;
}

export interface PortScanResult {
  ip: string;
  ports: PortResult[];
  hostnames: string[];
  totalVulns: number;
}

export interface CodeReviewResult {
  overallRisk: "critical" | "high" | "medium" | "low" | "safe";
  score: number;
  findings: CodeFinding[];
  summary: string;
  recommendations: string[];
  /** sast = pattern-only; gemini = AI only; sast+gemini = merged; heuristic kept for legacy */
  reviewSource?: "sast" | "gemini" | "sast+gemini" | "heuristic";
  providerNote?: string;
  staticFindingsCount?: number;
  aiFindingsCount?: number;
}

export interface CodeFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  line?: number;
  category: string;
  cwe?: string;
  fix?: string;
  /** Plain name of the weakness (filled by enricher if omitted) */
  vulnerability?: string;
  /** Business / security impact in simple English */
  impact?: string;
  /** Actionable remediation (often same as fix; filled by enricher if omitted) */
  recommendation?: string;
  /** Short snippet from the flagged source line (first words / compact preview) */
  evidence?: string;
  /** Rule-based scan vs LLM vs optional Semgrep subprocess */
  source?: "sast" | "ai" | "semgrep";
}

export interface AIReport {
  executiveSummary: string;
  riskLevel: string;
  topFindings: string[];
  recommendations: string[];
  complianceNotes: string[];
}
