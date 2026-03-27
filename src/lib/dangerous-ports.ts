/** Ports commonly abused when exposed to the internet (Shodan-style context). */

export const CRITICAL_EXPOSED_PORTS: Record<number, { risk: "critical" | "high" | "medium"; reason: string }> = {
  21: { risk: "high", reason: "FTP often weak auth / cleartext" },
  23: { risk: "critical", reason: "Telnet is cleartext and frequently exploited" },
  25: { risk: "medium", reason: "Open SMTP can be abused for relay/spam" },
  135: { risk: "high", reason: "MSRPC — common Windows attack surface" },
  139: { risk: "high", reason: "NetBIOS — lateral movement / enumeration" },
  445: { risk: "critical", reason: "SMB — ransomware / EternalBlue-class risk if misconfigured" },
  1433: { risk: "high", reason: "MSSQL — brute force / default creds" },
  1521: { risk: "high", reason: "Oracle listener exposure" },
  27017: { risk: "critical", reason: "MongoDB often deployed without auth historically" },
  3306: { risk: "high", reason: "MySQL — brute force / weak defaults" },
  5432: { risk: "high", reason: "PostgreSQL exposure" },
  3389: { risk: "critical", reason: "RDP — common ransomware entry" },
  5900: { risk: "high", reason: "VNC often weak or no password" },
  6379: { risk: "critical", reason: "Redis — frequently unauthenticated" },
  9200: { risk: "high", reason: "Elasticsearch — data exfiltration" },
  11211: { risk: "high", reason: "Memcached — amplification / DDoS" },
  5984: { risk: "high", reason: "CouchDB admin interface" },
  8080: { risk: "medium", reason: "Alternate HTTP — often admin panels" },
  8443: { risk: "medium", reason: "Alternate HTTPS — admin / APIs" },
};
