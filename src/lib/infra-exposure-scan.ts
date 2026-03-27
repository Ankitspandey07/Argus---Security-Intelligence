/**
 * WordPress wp-cron (Nuclei-style) plus common infra misconfigs: Swagger/OpenAPI, heapdump, Spring Actuator, Prometheus metrics.
 */

const UA = "Argus-InfraExposure/1.0 (by Ankit Pandey)";
const FETCH_TIMEOUT_MS = 11000;
const MAX_READ = 140_000;

export type InfraCategory = "wp-cron" | "swagger" | "heapdump" | "actuator" | "prometheus";

export type InfraCheck = {
  path: string;
  category: InfraCategory;
  status: number;
  bodyLength: number;
  exposed: boolean;
  matcher: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  recommendation: string;
};

function looksLikeHtml(body: string): boolean {
  return /<\s*html|<!DOCTYPE/i.test(body.slice(0, 4000));
}

function detectPrometheus(body: string): boolean {
  if (body.length < 220) return false;
  if (looksLikeHtml(body)) return false;
  if (!/#\s*HELP/.test(body) && !/#\s*TYPE/.test(body)) return false;
  return /^[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?\s+[-+]?[0-9.eE+-]+(\s|$)/m.test(body);
}

function detectSwagger(body: string, status: number): boolean {
  if (status !== 200) return false;
  const s = body.slice(0, 80_000);
  if (/"openapi"\s*:\s*"/.test(s) && /"paths"\s*:\s*\{/.test(s)) return true;
  if (/"swagger"\s*:\s*["']?2/.test(s) && /"paths"/.test(s)) return true;
  if (/swagger-ui|Swagger UI|swaggerui/i.test(s)) return true;
  return false;
}

function detectHeapdump(body: ArrayBuffer, textFallback: string, contentDisposition: string | null): boolean {
  const cd = contentDisposition || "";
  if (/heapdump|hprof|heap_dump/i.test(cd)) return true;
  const u8 = new Uint8Array(body.slice(0, 32));
  const ascii = String.fromCharCode(...u8);
  if (ascii.includes("JAVA PROFILE")) return true;
  if (textFallback.length > 400 && /"threadName"\s*:/.test(textFallback) && /"stackTrace"/.test(textFallback)) {
    return true;
  }
  return false;
}

function detectActuatorJson(body: string, path: string): boolean {
  if (!path.includes("actuator")) return false;
  if (path.includes("heapdump")) return false;
  if (path.includes("prometheus")) return false;
  try {
    const j = JSON.parse(body.slice(0, 200_000)) as Record<string, unknown>;
    if (j._links && typeof j._links === "object") return true;
    if (typeof j.status === "string" && typeof j.components === "object") return true;
    if (Array.isArray(j.propertySources)) return true;
    if (j.activeProfiles && Array.isArray(j.activeProfiles)) return true;
  } catch {
    /* ignore */
  }
  if (/"_links"\s*:\s*\{/.test(body) && /actuator/i.test(body)) return true;
  if (/"propertySources"\s*:\s*\[/.test(body) && /actuator/i.test(path)) return true;
  return false;
}

function wpCronMatch(status: number, body: string): { exposed: boolean; matcher: string } {
  const len = body.length;
  const hasHtml = /<\s*html|<!DOCTYPE/i.test(body);
  if (status === 200 && len < 100 && !hasHtml) return { exposed: true, matcher: "empty-200" };
  if (status === 204) return { exposed: true, matcher: "no-content" };
  if (status === 403) return { exposed: true, matcher: "forbidden" };
  return { exposed: false, matcher: "none" };
}

export async function runWpCronChecks(origin: string): Promise<InfraCheck[]> {
  const base = origin.replace(/\/$/, "");
  const paths = ["/wp-cron.php", "/wp/wp-cron.php"];
  const checks: InfraCheck[] = [];

  for (const path of paths) {
    const target = base + path;
    try {
      const res = await fetch(target, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        headers: { "User-Agent": UA },
      });
      const body = await res.text();
      const { exposed, matcher } = wpCronMatch(res.status, body);
      checks.push({
        path,
        category: "wp-cron",
        status: res.status,
        bodyLength: body.length,
        exposed,
        matcher,
        severity: exposed ? "medium" : "info",
        recommendation: exposed
          ? "Restrict wp-cron.php to localhost or disable public access; use system cron with DISABLE_WP_CRON."
          : "No Nuclei-style wp-cron exposure pattern matched (still verify WordPress hardening).",
      });
    } catch {
      checks.push({
        path,
        category: "wp-cron",
        status: 0,
        bodyLength: 0,
        exposed: false,
        matcher: "error",
        severity: "info",
        recommendation: "Could not reach endpoint (network/DNS).",
      });
    }
  }
  return checks;
}

const INFRA_PATHS: { path: string; category: Exclude<InfraCategory, "wp-cron"> }[] = [
  { path: "/swagger-ui.html", category: "swagger" },
  { path: "/swagger-ui/index.html", category: "swagger" },
  { path: "/swagger/index.html", category: "swagger" },
  { path: "/v3/api-docs", category: "swagger" },
  { path: "/v2/api-docs", category: "swagger" },
  { path: "/swagger.json", category: "swagger" },
  { path: "/openapi.json", category: "swagger" },
  { path: "/actuator/heapdump", category: "heapdump" },
  { path: "/heapdump", category: "heapdump" },
  { path: "/heapdump.hprof", category: "heapdump" },
  { path: "/actuator", category: "actuator" },
  { path: "/actuator/health", category: "actuator" },
  { path: "/actuator/env", category: "actuator" },
  { path: "/actuator/prometheus", category: "prometheus" },
  { path: "/metrics", category: "prometheus" },
  { path: "/prometheus/metrics", category: "prometheus" },
];

export async function runInfraMisconfigChecks(origin: string): Promise<InfraCheck[]> {
  const base = origin.replace(/\/$/, "");
  const out: InfraCheck[] = [];

  for (const { path, category } of INFRA_PATHS) {
    const target = base + path;
    try {
      const res = await fetch(target, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        headers: { "User-Agent": UA, Accept: "*/*" },
      });
      const buf = await res.arrayBuffer();
      const text = new TextDecoder("utf-8", { fatal: false }).decode(buf).slice(0, MAX_READ);
      const status = res.status;
      const cd = res.headers.get("content-disposition");

      let exposed = false;
      let matcher = "none";
      let severity: InfraCheck["severity"] = "info";
      let recommendation = "No distinctive exposure pattern matched for this path.";

      if (category === "swagger") {
        exposed = detectSwagger(text, status);
        matcher = exposed ? "openapi/swagger-content" : "no-match";
        severity = exposed ? "high" : "info";
        recommendation = exposed
          ? "Do not expose API docs publicly; require auth, IP allowlist, or disable in production."
          : "No obvious Swagger/OpenAPI UI or spec detected in response.";
      } else if (category === "heapdump") {
        exposed = status === 200 && detectHeapdump(buf, text, cd);
        matcher = exposed ? "heapdump-signature" : "no-match";
        severity = exposed ? "critical" : "info";
        recommendation = exposed
          ? "Heap dumps contain memory secrets — disable actuator heapdump; restrict /actuator to trusted networks."
          : "No heap dump / HPROF signature in response prefix.";
      } else if (category === "actuator") {
        exposed = status === 200 && detectActuatorJson(text, path);
        matcher = exposed ? "spring-actuator-json" : "no-match";
        severity = exposed ? "high" : "info";
        recommendation = exposed
          ? "Lock down Spring Boot Actuator (management.endpoints, Spring Security); never expose /actuator/env publicly."
          : "No Spring Boot actuator-style JSON detected.";
      } else if (category === "prometheus") {
        exposed = status === 200 && detectPrometheus(text);
        matcher = exposed ? "prometheus-text" : "no-match";
        severity = exposed ? "medium" : "info";
        recommendation = exposed
          ? "Protect /metrics behind auth or network policy; metrics can leak service topology and labels."
          : "No Prometheus # HELP / # TYPE exposition pattern detected.";
      }

      out.push({
        path,
        category,
        status,
        bodyLength: text.length,
        exposed,
        matcher,
        severity,
        recommendation,
      });
    } catch {
      out.push({
        path,
        category,
        status: 0,
        bodyLength: 0,
        exposed: false,
        matcher: "error",
        severity: "info",
        recommendation: "Could not reach endpoint (network/DNS).",
      });
    }
  }

  return out;
}
