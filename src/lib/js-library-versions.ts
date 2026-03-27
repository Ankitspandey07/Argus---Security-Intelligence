import semver from "semver";

/**
 * Heuristic version fingerprints inside minified or source JS (Retire/Wappalyzer-style).
 * Keys must match Retire.js jsrepository.json top-level names where possible.
 */
export interface JsLibraryVersionHit {
  library: string;
  version: string;
  evidence: string;
}

const SLICE = 180_000;

function coerceVer(s: string): string | null {
  const c = semver.coerce(s);
  return c ? c.version : null;
}

export function extractLibraryVersionsFromJs(content: string, url: string): JsLibraryVersionHit[] {
  const slice = content.slice(0, SLICE);
  const hits: JsLibraryVersionHit[] = [];
  const u = url.toLowerCase();

  const add = (library: string, version: string, evidence: string) => {
    const v = coerceVer(version);
    if (!v) return;
    hits.push({ library, version: v, evidence });
  };

  // jQuery: /*! jQuery v3.6.0 | ... */  or  jQuery v1.11.1
  let m = slice.match(/jQuery\s+v?(\d+\.\d+\.\d+)/i);
  if (m) add("jquery", m[1], "banner: jQuery v…");
  m = slice.match(/jquery[/-](\d+\.\d+\.\d+)/i);
  if (m && !hits.some((h) => h.library === "jquery")) add("jquery", m[1], "jquery-x.y.z pattern");

  // AngularJS
  m = slice.match(/AngularJS\s+v?(\d+\.\d+\.\d+)/i);
  if (m) add("angularjs", m[1], "AngularJS banner");
  m = slice.match(/angular\.js\s+v?(\d+\.\d+\.\d+)/i);
  if (m && !hits.some((h) => h.library === "angularjs")) add("angularjs", m[1], "angular.js banner");

  // Lodash / Underscore
  m = slice.match(/lodash\s+([\d.]+)/i);
  if (m) add("lodash", m[1], "lodash version string");
  m = slice.match(/underscore\.js\s+([\d.]+)/i);
  if (m) add("underscore", m[1], "underscore banner");

  // Moment
  m = slice.match(/Moment\.js\s+([\d.]+)/i);
  if (m) add("moment", m[1], "Moment.js banner");
  m = slice.match(/VERSION\s*=\s*["']([\d.]+)["'][\s\S]{0,80}moment/i);
  if (m && !hits.some((h) => h.library === "moment")) add("moment", m[1], "moment VERSION");

  // Handlebars
  m = slice.match(/Handlebars\.VERSION\s*=\s*["']([\d.]+)["']/i);
  if (m) add("handlebars", m[1], "Handlebars.VERSION");
  m = slice.match(/handlebars[/-](\d+\.\d+\.\d+)/i);
  if (m && !hits.some((h) => h.library === "handlebars")) add("handlebars", m[1], "handlebars path-like");

  // Vue 2 banner
  m = slice.match(/Vue\.js\s+v?(\d+\.\d+\.\d+)/i);
  if (m) add("vue", m[1], "Vue.js banner");
  // Vue 3
  m = slice.match(/version\s*:\s*["'](\d+\.\d+\.\d+)["'][\s\S]{0,120}createApp/i);
  if (m && !hits.some((h) => h.library === "vue")) add("vue", m[1], "vue runtime signature");

  // Bootstrap
  m = slice.match(/\*\s*Bootstrap\s+v?(\d+\.\d+\.\d+)/i);
  if (m) add("bootstrap", m[1], "Bootstrap banner");

  // DOMPurify
  m = slice.match(/DOMPurify\s*[=(]\s*["']?(\d+\.\d+\.\d+)/i);
  if (m) add("dompurify", m[1], "DOMPurify version");

  // Axios
  m = slice.match(/axios\/(\d+\.\d+\.\d+)/i);
  if (m) add("axios", m[1], "axios/x.y.z");

  // URL-only fallbacks for npm CDNs (body may be opaque bundle)
  const cdnPkg =
    u.match(/unpkg\.com\/(?:@[^/]+\/)?([^/@]+)@(\d+\.\d+[^/?#]*)/i) ||
    u.match(/cdn\.jsdelivr\.net\/npm\/(?:@[^/]+\/)?([^/@]+)@(\d+\.\d+[^/?#]*)/i) ||
    u.match(/cdnjs\.cloudflare\.com\/ajax\/libs\/([^/]+)\/(\d+\.\d+[^/]*)\//i);
  if (cdnPkg) {
    const name = cdnPkg[1].toLowerCase().replace(/\.min$/, "");
    const ver = cdnPkg[2];
    const map: Record<string, string> = {
      jquery: "jquery",
      "angular.js": "angularjs",
      angular: "angularjs",
      lodash: "lodash",
      moment: "moment",
      vue: "vue",
      axios: "axios",
      "twitter-bootstrap": "bootstrap",
      bootstrap: "bootstrap",
      handlebars: "handlebars",
      underscore: "underscore",
      dompurify: "dompurify",
    };
    const lib = map[name] || name;
    if (!hits.some((h) => h.library === lib)) add(lib, ver, "CDN URL version segment");
  }

  const dedupe = new Map<string, JsLibraryVersionHit>();
  for (const h of hits) {
    const k = `${h.library}:${h.version}`;
    if (!dedupe.has(k)) dedupe.set(k, h);
  }
  return [...dedupe.values()];
}
