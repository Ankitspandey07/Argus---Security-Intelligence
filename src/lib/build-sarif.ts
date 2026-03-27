import type { ScanResult, SSLResult, PortScanResult } from "@/lib/types";

/** Minimal SARIF 2.1.0 for CI viewers — generated client-side, no server storage. */

export function buildSecuritySarif(args: {
  scan?: ScanResult;
  ssl?: SSLResult;
  ports?: PortScanResult & { highRiskOpenPorts?: { port: number; service: string }[] };
}): Record<string, unknown> {
  const results: Record<string, unknown>[] = [];
  const scan = args.scan;

  if (scan) {
    for (const h of scan.headers) {
      if (h.status === "pass") continue;
      results.push({
        ruleId: `argus.header.${h.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`,
        level: h.severity === "critical" || h.severity === "high" ? "error" : "warning",
        message: { text: `${h.name}: ${h.description}` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: `https://${scan.target.hostname}/` },
              region: { startLine: 1 },
            },
          },
        ],
      });
    }
  }

  if (args.ssl) {
    for (const v of args.ssl.vulnerabilities.filter((x) => x.vulnerable)) {
      results.push({
        ruleId: `argus.ssl.${v.name.replace(/\s+/g, "-").toLowerCase()}`,
        level: "error",
        message: { text: `${v.name}: ${v.description}` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: `https://${args.scan?.target.hostname ?? "target"}/` },
              region: { startLine: 1 },
            },
          },
        ],
      });
    }
  }

  if (args.ports?.highRiskOpenPorts?.length) {
    for (const p of args.ports.highRiskOpenPorts) {
      results.push({
        ruleId: "argus.port.high-risk",
        level: "warning",
        message: { text: `Open port ${p.port} (${p.service})` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: `tcp://${args.ports?.ip ?? scan?.target.hostname}:${p.port}` },
              region: { startLine: 1 },
            },
          },
        ],
      });
    }
  }

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Argus",
            informationUri: "https://owasp.org/www-project-web-security-testing-guide/",
            version: "1.0.0",
            rules: [],
          },
        },
        results,
      },
    ],
  };
}
