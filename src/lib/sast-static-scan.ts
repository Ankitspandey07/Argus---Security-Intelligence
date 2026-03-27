import type { CodeFinding, CodeReviewResult } from "@/lib/types";
import { lineEvidenceSnippet } from "@/lib/sast-evidence";

/**
 * Offline static pattern scan (SAST-style heuristics).
 * Runs without any LLM — similar in spirit to shallow Semgrep / legacy Fortify pattern packs.
 *
 * Maintainer documentation for every rule, categories, and FP guidance:
 * @see docs/sast-rules.md
 */

type Pattern = {
  re: RegExp;
  severity: CodeFinding["severity"];
  title: string;
  category: string;
  description: string;
  fix: string;
};

const PATTERNS: Pattern[] = [
  // JavaScript / TS / JSX
  { re: /\beval\s*\(/i, severity: "high", title: "eval()", category: "Injection", description: "Executes dynamic code from strings.", fix: "Remove eval; parse data with JSON.parse or safe parsers." },
  { re: /new\s+Function\s*\(/i, severity: "high", title: "new Function()", category: "Injection", description: "Compiles arbitrary string as code.", fix: "Use static functions or vetted expression engines." },
  { re: /dangerouslySetInnerHTML/i, severity: "medium", title: "dangerouslySetInnerHTML", category: "XSS", description: "Raw HTML into React DOM.", fix: "Sanitize (DOMPurify.sanitize) or avoid raw HTML." },
  {
    re: /\bif\s*\(\s*window\.\w+/,
    severity: "medium",
    title: "Branch on window.* global (DOM clobbering risk)",
    category: "XSS / client trust",
    description: "HTML id/name attributes can shadow window properties — injected markup may flip security gates (e.g. fake admin flags).",
    fix: "Do not trust window.* for auth; use server session/JWT claims or Symbol-scoped flags.",
  },
  { re: /\.innerHTML\s*=/i, severity: "medium", title: "innerHTML assignment", category: "XSS", description: "DOM XSS risk if data is user-controlled.", fix: "Prefer textContent or escaped templates." },
  { re: /document\.write\s*\(/i, severity: "low", title: "document.write", category: "XSS", description: "Discouraged; can inject markup.", fix: "Use DOM APIs." },
  { re: /\bsetTimeout\s*\(\s*['"`]/i, severity: "medium", title: "setTimeout with string", category: "Injection", description: "String argument is similar to eval.", fix: "Pass a function reference." },
  { re: /\bsetInterval\s*\(\s*['"`]/i, severity: "medium", title: "setInterval with string", category: "Injection", description: "String argument is similar to eval.", fix: "Pass a function reference." },
  { re: /child_process\.exec\s*\(|child_process\.execSync\s*\(/i, severity: "high", title: "Node exec with shell", category: "Command injection", description: "Shell interprets metacharacters in arguments.", fix: "Use execFile/spawn with array args; validate input." },
  {
    re: /(?<![a-zA-Z0-9_$])exec\s*\(\s*`[^`\n]*\$\{/,
    severity: "high",
    title: "exec() with shell command template literal",
    category: "Command injection",
    description:
      "Bare exec(…) (often from child_process) with a template string allows shell metacharacters and ${…} expansion — classic command injection when input is user-controlled.",
    fix: "Use execFile/spawn with argv array and shell: false; validate/sanitize IP/host inputs with strict allowlists.",
  },
  {
    re: /(?<![a-zA-Z0-9_$])exec\s*\(\s*["'][^"'\\]*["']\s*\+\s*/,
    severity: "high",
    title: "exec() building shell string with concatenation",
    category: "Command injection",
    description: "Shell command built by concatenating strings — user-controlled fragments can inject `;`, `|`, backticks, etc.",
    fix: "Never concatenate into a shell string; use spawn with an argument array.",
  },
  { re: /\bspawn\s*\([^)]*shell\s*:\s*true/i, severity: "high", title: "spawn({ shell: true })", category: "Command injection", description: "Shell expands user-controlled fragments.", fix: "shell: false and pass argv array." },
  // Python
  { re: /\bos\.system\s*\(/i, severity: "high", title: "os.system()", category: "Command injection", description: "Invokes shell with string.", fix: "Use subprocess.run with list args and shell=False." },
  { re: /\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True/i, severity: "high", title: "subprocess shell=True", category: "Command injection", description: "Shell injection on untrusted input.", fix: "shell=False; pass sequence of arguments." },
  { re: /\bpickle\.loads?\s*\(/i, severity: "high", title: "pickle load", category: "Deserialization", description: "Arbitrary code execution on untrusted pickle.", fix: "Use JSON or explicit schemas." },
  {
    re: /\byaml\.load\s*\((?![^)\n]*SafeLoader)[^)]*\)/i,
    severity: "high",
    title: "yaml.load",
    category: "Deserialization",
    description: "Unsafe unless Loader=SafeLoader (multi-line calls may still false-positive — use safe_load).",
    fix: "yaml.safe_load only, or yaml.load(..., Loader=yaml.SafeLoader) on the same line.",
  },
  { re: /\bmarshal\.loads?\s*\(/i, severity: "high", title: "marshal load", category: "Deserialization", description: "Unsafe deserialization.", fix: "Do not unmarshal untrusted bytes." },
  { re: /\bshelve\.open\s*\(/i, severity: "medium", title: "shelve / pickle persistence", category: "Deserialization", description: "Built on pickle.", fix: "Avoid for untrusted paths or data." },
  // SQL (generic) — concat with request-like symbols OR quoted SQL + any variable (Node/PHP style)
  {
    re: /(?:SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,160}\+\s*(?:req\.|request\.|params|query|body|input|_|argv|getParameter)/i,
    severity: "high",
    title: "SQL string concatenation",
    category: "SQL injection",
    description: "User input may flow into SQL text.",
    fix: "Parameterized queries only.",
  },
  {
    re: /["'][^"'\\]*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)[^"'\\]*["']\s*\+\s*[a-zA-Z_$][\w$]*/i,
    severity: "critical",
    title: "SQL query built by concatenating a string literal with a variable",
    category: "SQL injection",
    description:
      "SQL text ending in a quote then `+ variable` is a strong SQL injection indicator (e.g. sqlite/mysql/pg drivers need bound parameters, not string building).",
    fix: "Use prepared statements / parameterized queries; never append user id or search terms into SQL strings.",
  },
  // Path traversal — `..\` must not match the `..\` inside C string ellipsis `"...\n"` (dots 2–3 + backslash)
  {
    re: /(?:\.\.\/)|(?<!\.)(?:\.\.\\)|%2e%2e%2f/i,
    severity: "medium",
    title: "Path traversal sequence",
    category: "Path traversal",
    description: "Parent-directory segments in paths (../, ..\\, or URL-encoded).",
    fix: "Canonicalize paths; block ..; use allowlists.",
  },
  // SSRF hints
  { re: /(?:fetch|axios|http\.get|requests\.(?:get|post)|urllib\.request)\s*\([^)]*(?:params|query|url)\s*[=\[][^)]*(?:req\.|request\.|input)/i, severity: "medium", title: "HTTP client with request-derived URL", category: "SSRF", description: "URL or host may be user-controlled.", fix: "Allowlist hosts; block private IP ranges." },
  // Secrets
  {
    re: /(password|secret|api[_-]?key|private[_-]?key|auth[_-]?token|(?:admin|access)(?:_|-)?token|(?:admin|access)Token|bearer[_-]?secret)\s*[:=]\s*['"][^'"]{6,}['"]/i,
    severity: "high",
    title: "Possible hardcoded secret",
    category: "Secrets",
    description: "Literal secret-like assignment.",
    fix: "Use env / vault; rotate if exposed.",
  },
  {
    re: /req\.headers\s*\[\s*['"]authorization['"]\s*\]\s*={1,3}\s*['"][^'"]{4,}['"]/i,
    severity: "high",
    title: "Authorization header compared to a fixed string literal",
    category: "Broken access control",
    description:
      "Static comparison of Authorization to a hardcoded token is brittle (secret in source, no rotation, often no timing-safe compare) and is not a substitute for real session/JWT/crypto verification.",
    fix: "Use environment-backed secrets, constant-time comparison if comparing secrets, and standard auth middleware (sessions, signed JWTs, OAuth2).",
  },
  {
    re: /req\.headers\s*\[\s*['"]authorization['"]\s*\]\s*===?\s*[a-zA-Z_$][\w$]*/i,
    severity: "high",
    title: "Authorization header compared to a variable (weak / custom token check)",
    category: "Broken access control",
    description:
      "Comparing the raw Authorization header to a variable is often a custom bearer/API-key gate. It is easy to get wrong (no scheme parsing, timing leaks, token in code or config) and is not equivalent to vetted JWT/session middleware.",
    fix: "Use standard auth libraries (Passport, oauth2-server, jose/jwt.verify); parse Bearer tokens; store secrets in env/KMS; prefer constant-time compares for secrets.",
  },
  { re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "critical", title: "PEM private key in file", category: "Secrets", description: "Private key material in snippet.", fix: "Remove from repo; rotate key." },
  /** Canonical (20-char) and placeholder styles (e.g. AKIA-SUPER-SECRET-…) */
  {
    re: /\bAKIA[A-Z0-9._-]{10,48}\b/,
    severity: "critical",
    title: "AWS access key id (AKIA*) pattern",
    category: "Secrets",
    description: "Looks like an AWS access key id (standard or non-canonical literal).",
    fix: "Revoke; use IAM roles / env vars; never commit.",
  },
  {
    re: /\b(?:AWS|Secret|Access)[A-Za-z0-9_]*(?:Key|Secret|ID|Id)\b\s*=\s*["'][^"'\n]{6,}["']/i,
    severity: "critical",
    title: "Hardcoded cloud/API key style constant",
    category: "Secrets",
    description: "Identifier suggests credentials assigned from a string literal.",
    fix: "Load from environment or secret manager; rotate any exposed value.",
  },
  {
    re: /\bghp_[a-zA-Z0-9]{20,}\b/,
    severity: "critical",
    title: "GitHub PAT (ghp_)",
    category: "Secrets",
    description: "Classic GitHub personal access token format (length may vary; verify not a placeholder).",
    fix: "Revoke token; use ${{ secrets.* }} or OIDC; never commit PATs.",
  },
  { re: /github_pat_[a-zA-Z0-9_]{20,}/, severity: "critical", title: "GitHub fine-grained PAT pattern", category: "Secrets", description: "Fine-grained PAT prefix.", fix: "Revoke and replace via secrets management." },
  { re: /sk_live_[0-9a-zA-Z]{24,}/, severity: "critical", title: "Stripe live secret key pattern", category: "Secrets", description: "sk_live_* indicates Stripe secret.", fix: "Roll key in Stripe dashboard; use restricted keys server-side only." },
  {
    re: /\bpk_live_[0-9a-zA-Z]{24,}/,
    severity: "medium",
    title: "Stripe publishable key (pk_live_) in source",
    category: "Secrets",
    description: "Publishable keys are not secret like sk_live_, but hardcoding couples environments and aids fraud/abuse recon — prefer env or dashboard config.",
    fix: "Load publishable key from build-time env; never mix live/test keys; monitor for key misuse.",
  },
  { re: /xox[abpr]-[0-9a-zA-Z-]{10,}/, severity: "critical", title: "Slack token pattern", category: "Secrets", description: "Bot/user OAuth token style.", fix: "Revoke in Slack admin; store in vault." },
  // Crypto weak
  { re: /\b(md5|sha1)\s*\(/i, severity: "low", title: "Weak hash", category: "Crypto", description: "MD5/SHA-1 not for security contexts.", fix: "SHA-256+ or dedicated password hashes." },
  { re: /Math\.random\s*\(\)/i, severity: "medium", title: "Math.random for security context", category: "Crypto", description: "Not cryptographically secure.", fix: "Use crypto.getRandomValues / secrets module." },
  { re: /random\.random\s*\(\)/i, severity: "medium", title: "random.random for tokens", category: "Crypto", description: "Python random is not for secrets.", fix: "Use secrets.token_* ." },
  // PHP
  { re: /\b(?:mysql_|mysqli_query)\s*\([^,]+,\s*\$/i, severity: "medium", title: "PHP DB query with variable SQL", category: "SQL injection", description: "Verify query is parameterized.", fix: "Prepared statements." },
  { re: /\bunserialize\s*\(\s*\$/i, severity: "high", title: "PHP unserialize", category: "Deserialization", description: "Unsafe on untrusted input.", fix: "Avoid or use allowed_classes whitelist." },
  { re: /\binclude\s*\(\s*\$_|\brequire\s*\(\s*\$_/i, severity: "critical", title: "Dynamic include from superglobal", category: "LFI/RCE", description: "User may control file path.", fix: "Allowlist paths." },
  // Java
  { re: /Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(/i, severity: "high", title: "Runtime.exec", category: "Command injection", description: "Process execution — validate arguments.", fix: "Use ProcessBuilder with list; no shell." },
  { re: /ObjectInputStream|readObject\s*\(/i, severity: "medium", title: "Java deserialization", category: "Deserialization", description: "ObjectInputStream on untrusted bytes is risky.", fix: "Avoid or use safe allowlists / signing." },
  // Go
  { re: /exec\.Command\s*\(\s*["'`]sh["'`]/i, severity: "high", title: "exec.Command shell", category: "Command injection", description: "Invoking shell expands user input.", fix: "Invoke binary directly with argv." },
  {
    re: /\bInsecureSkipVerify\s*:\s*true\b/,
    severity: "high",
    title: "TLS InsecureSkipVerify: true",
    category: "TLS misconfiguration",
    description: "Disables certificate verification on TLS clients.",
    fix: "Use proper roots; pin only when necessary with custom verification.",
  },
  {
    re: /\bhttp\.Get\s*\(\s*[^"'`\s\n]/,
    severity: "critical",
    title: "Go http.Get with non-literal URL",
    category: "SSRF",
    description: "Outbound GET to a URL expression — often user-controlled (SSRF, metadata access).",
    fix: "Parse URL; allowlist hosts; block private/link-local ranges; use bounded client.",
  },
  {
    re: /\bioutil\.ReadFile\s*\(\s*["'][^"']*["']\s*\+\s*|os\.ReadFile\s*\(\s*["'][^"']*["']\s*\+\s*/,
    severity: "critical",
    title: "Go ReadFile with path concatenation",
    category: "Path traversal",
    description: "User-influenced segment appended to a path prefix.",
    fix: "filepath.Clean + root check; reject ..; allowlist filenames.",
  },
  // Generic debug
  { re: /\bdebugger\s*;/i, severity: "low", title: "debugger statement", category: "Quality", description: "May leak logic in production.", fix: "Remove before release." },
  { re: /TODO\s*\(?\s*security|FIXME\s*\(?\s*sec/i, severity: "info", title: "Security TODO/FIXME", category: "Process", description: "Tracked security debt marker.", fix: "Resolve before production." },
];

/**
 * Multiline / structural patterns (taint-adjacent): SQL interpolation, XSS build-up, path concat, etc.
 * Scanned against the full pasted source, not line-by-line.
 */
const DEEP_PATTERNS: Pattern[] = [
  {
    re: /\.execute\s*\(\s*f["'`]/,
    severity: "critical",
    title: "SQL injection: f-string / format string in execute()",
    category: "SQL injection",
    description: "User-controlled values in f-strings become SQL injection when passed to cursor.execute().",
    fix: "Parameterized queries: cursor.execute(\"SELECT … WHERE id = ?\", (id,)).",
  },
  {
    re: /\.execute\s*\(\s*["'][^"'`\n]*%[sd][^"'`\n]*["']\s*%\s*\(/,
    severity: "critical",
    title: "SQL injection: printf-style SQL to execute()",
    category: "SQL injection",
    description: "String % formatting builds SQL from variables — classic SQLi if any part is untrusted.",
    fix: "Use bound parameters; never % format SQL strings.",
  },
  {
    re: /f["'][^"'\n]{0,800}?(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|VALUES\s*\()[^"'\n]{0,800}?\{[^}]+\}/i,
    severity: "critical",
    title: "SQL keywords inside f-string with {…} interpolation",
    category: "SQL injection",
    description: "SQL text built with f-string / brace interpolation flows to the database.",
    fix: "Use placeholders (? / %s with tuple) and driver parameterization.",
  },
  {
    re: /(?:query|sql)\s*=\s*f["'][^"']*\{[^}]+\}/i,
    severity: "high",
    title: "SQL query built as f-string",
    category: "SQL injection",
    description: "Assigning an f-string containing {variables} to a SQL query variable.",
    fix: "Parameterize; separate SQL structure from data.",
  },
  {
    re: /["'][^"'\n]*<[a-zA-Z][^"']*["']\s*\+\s*(?:user_input|username|password|request\.|req\.|params|body|form)/i,
    severity: "critical",
    title: "XSS: HTML string concatenation with user-like input",
    category: "XSS",
    description: "Markup built by concatenating strings with variables that may hold user content.",
    fix: "Escape output, use templates with auto-escaping, or sanitize HTML.",
  },
  {
    re: /(?:html|HTML|inner|buf|body|content|response|res|out|page|fragment|markup|tpl|stringBuilder|sb)\w*\s*\+=\s*["'][^"']*["']\s*\+\s*\w+/,
    severity: "medium",
    title: "Incremental HTML/string build with concatenation",
    category: "XSS",
    description: "Likely HTML/response buffer built by concatenation — verify escaping if any fragment is user-controlled.",
    fix: "Use a framework template or html.escape / bleach.",
  },
  {
    re: /return\s+[^;\n]*\+\s*(?:user_input|username|request\.|req\.)/i,
    severity: "high",
    title: "Return value built with string concat to user-derived data",
    category: "XSS",
    description: "Returned HTML/text may reflect unsanitized input.",
    fix: "Escape or encode for the response context.",
  },
  {
    re: /(?:open|file)\s*\(\s*["'][^"']+["']\s*\+\s*\w+\s*\)/,
    severity: "high",
    title: "Path traversal: open() with string concat",
    category: "Path traversal",
    description: "Filename or segment concatenated into a path — classic LFI if user-controlled.",
    fix: "Use os.path.join with basename allowlist; resolve realpath under a root.",
  },
  {
    re: /=\s*["'][^"']*(?:\/|\\)(?:uploads?|var\/www|tmp|home)[^"']*["']\s*\+\s*\w+/i,
    severity: "high",
    title: "Filesystem path built from fixed prefix + variable",
    category: "Path traversal",
    description: "User-influenced segment appended to a sensitive directory path.",
    fix: "Validate filename; reject ..; use secure join + allowlist.",
  },
  {
    re: /query\s*=\s*["'][^"'\n]*%[sd][^"'\n]*["']\s*%\s*\([^)]*\)[\s\S]{0,500}?\.execute\s*\(\s*query\s*\)/i,
    severity: "critical",
    title: "SQL injection: %-formatted query passed to execute()",
    category: "SQL injection",
    description: "SQL string built with % formatting then executed — same class as string concat SQLi.",
    fix: "Use parameterized execute(\"…\", (username, password)).",
  },
  {
    re: /def\s+\w+\s*\([^)]*=\s*\[\s*\]\s*\)/,
    severity: "medium",
    title: "Mutable default argument (list/dict)",
    category: "Logic bug",
    description: "Default [] or {} is shared across calls — subtle state bugs (Bandit B006).",
    fix: "Use None and assign new list inside the function.",
  },
  {
    re: /except\s*:\s*(?:pass\s*)?(?:#|$|\n)/,
    severity: "medium",
    title: "Bare except (swallows all errors)",
    category: "Reliability / security",
    description: "Catches KeyboardInterrupt/SystemExit and hides failures — can mask injection errors.",
    fix: "except Exception as e: log and handle specifically.",
  },
  {
    re: /\bET\.fromstring\s*\(/,
    severity: "medium",
    title: "xml.etree.fromstring on string input",
    category: "XML / XXE",
    description: "Parsing untrusted XML can be unsafe depending on parser config; prefer defusedxml for untrusted data.",
    fix: "Use defusedxml.ElementTree or disable external entities.",
  },
  {
    re: /(?:os\.system|popen)\s*\(\s*["'`][^"'`]*\+/i,
    severity: "high",
    title: "Python shell command built with string concatenation",
    category: "Command injection",
    description: "os.system/popen builds a shell string with + — user input can inject metacharacters.",
    fix: "Use subprocess.run([\"binary\", \"arg\"], shell=False) with a fixed argv list; validate inputs.",
  },
  {
    re: /\.raw_query\s*\(|\.extra\s*\(\s*where\s*=\s*["'][^"']*\{/i,
    severity: "high",
    title: "ORM raw SQL / .extra with interpolation",
    category: "SQL injection",
    description: "Django-style raw fragments may embed user data unsafely.",
    fix: "Use ORM filters or parameterized raw().",
  },
];

/** Node / Express / MongoDB-style issues (targeted, conservative regexes). */
const NODE_AND_EXPRESS_DEEP_PATTERNS: Pattern[] = [
  {
    re: /\.findOne\s*\(\s*\{[\s\S]{0,900}?username:\s*username[\s\S]{0,700}?password:\s*password[\s\S]{0,400}?\}/,
    severity: "critical",
    title: "MongoDB findOne() with request-scoped username/password",
    category: "NoSQL injection",
    description:
      "Passing username/password variables from the HTTP layer into findOne({...}) allows operator-injection logins when bodies are parsed as JSON (e.g. {\"$ne\": null}).",
    fix: "Coerce credentials to strings; reject objects/arrays; validate schema; use a hardened auth library or separate identity service.",
  },
  {
    re: /axios\.(?:get|post|request|head)\s*\(\s*targetUrl\b/,
    severity: "critical",
    title: "Outbound HTTP (axios) with user-controlled URL",
    category: "SSRF",
    description:
      "Fetching a URL taken from user input can hit internal IPs, metadata endpoints, or file URLs. Attackers use SSRF to scan networks and steal cloud credentials.",
    fix: "Allowlist hosts/schemes; block RFC1918 and link-local ranges; use a dedicated preview service with timeouts and size limits.",
  },
  {
    re: /axios\.(?:get|post|request)\s*\(\s*req\.body\b/,
    severity: "critical",
    title: "Outbound HTTP (axios) with req.body-derived URL",
    category: "SSRF",
    description: "Same SSRF class: the URL object likely comes straight from the client body without validation.",
    fix: "Parse and validate URL; allowlist destinations; never pass raw body fields to HTTP clients.",
  },
  {
    re: /\bfetch\s*\(\s*targetUrl\b|\bfetch\s*\(\s*req\.body\b/,
    severity: "high",
    title: "fetch() with user-derived URL",
    category: "SSRF",
    description: "Native fetch to a client-controlled target is an SSRF risk unless URL and network policy are strictly validated.",
    fix: "Allowlist hosts; resolve and block private IPs; short timeouts; response size caps.",
  },
  {
    re: /\.(?:send|json)\s*\([^)]*\b(?:err|error)\.stack\b/,
    severity: "high",
    title: "Stack trace sent in HTTP response",
    category: "Information disclosure",
    description:
      "Returning err.stack (or similar) leaks file paths, framework versions, and logic to attackers and simplifies exploitation.",
    fix: "Log full errors server-side only; respond with a generic message and correlation id.",
  },
  {
    re: /deleteOne\s*\(\s*\{\s*_id:\s*(?!new\s+ObjectId\s*\(|ObjectId\s*\()\s*[a-zA-Z_]\w*\s*\}/,
    severity: "medium",
    title: "MongoDB _id from variable without ObjectId()",
    category: "Data integrity / IDOR",
    description:
      "req.params ids are strings; passing them as bare _id often mismatches BSON ObjectId, causing failed deletes or weak matching unless the driver coerces safely.",
    fix: "Validate hex length; use ObjectId.createFromHexString / driver helpers; enforce ownership checks.",
  },
  {
    re: /path\.join\s*\(\s*__dirname\s*,[\s\S]{0,900}?\.sendFile\s*\(/i,
    severity: "high",
    title: "res.sendFile after path.join under __dirname (path traversal / LFI risk)",
    category: "Path traversal",
    description:
      "Building a filesystem path with path.join(__dirname, …, user-influenced name) and passing it to sendFile can allow ../ escapes or absolute paths unless the final segment is strictly validated.",
    fix: "Resolve real path, ensure it stays under a fixed root; use path.basename + allowlist; reject .. and absolute paths.",
  },
];

/** PHP-focused structural rules (LFI, uploads, type juggling, reflected XSS, etc.). */
const PHP_DEEP_PATTERNS: Pattern[] = [
  {
    re: /(?:md5|sha1)\s*\(\s*\$_(?:POST|GET|REQUEST)\s*\[[^\]]+\]\s*\)[\s\S]{0,900}?if\s*\(\s*\$[a-zA-Z_]\w*\s*==\s*\$[a-zA-Z_]\w*\s*\)/i,
    severity: "critical",
    title: "PHP loose equality (==) on password/hash comparison",
    category: "Authentication / type juggling",
    description:
      "Using == (not ===) to compare digests enables PHP type juggling and magic-hash collisions (e.g. 0e* scientific-notation strings). Attackers can sometimes forge matching hashes without knowing the password.",
    fix: "Use === with hash_equals() for timing-safe comparison; store passwords with password_hash() / password_verify(); never MD5 for credentials.",
  },
  {
    re: /\b(?:include|require)(?:_once)?\s*\(\s*["'][^"'\\]*["']\s*\.\s*\$/i,
    severity: "critical",
    title: "Local file inclusion: include/require with concatenated path",
    category: "LFI / RCE",
    description:
      "Building include/require paths by concatenating literals with variables often lets attackers traverse directories (../) or load attacker-controlled files, leading to disclosure or code execution.",
    fix: "Allowlist template names; map user input to fixed filenames; never pass raw request parameters into include paths.",
  },
  {
    re: /\$_FILES\s*\[[^\]]+\][\s\S]{0,2600}?\bmove_uploaded_file\s*\(/i,
    severity: "critical",
    title: "File upload without visible validation (RCE risk)",
    category: "Unrestricted upload",
    description:
      "Saving $_FILES to disk (especially under the web root) without strict type/size checks often allows uploading executable scripts (.php, .phtml) that attackers invoke over HTTP for remote code execution.",
    fix: "Validate MIME/extension with finfo; store outside web root or deny script execution; generate random server-side names; enforce size limits.",
  },
  {
    re: /echo\s+["'][^"']{0,220}["']\s*\.\s*\$(?:query|search|page|_GET|_POST|_REQUEST)\b/i,
    severity: "high",
    title: "PHP reflected XSS risk: echo builds HTML from request data",
    category: "XSS",
    description:
      "Concatenating request-derived variables into echoed HTML typically reflects input without encoding, enabling stored/reflected XSS when victims load crafted URLs.",
    fix: "Use htmlspecialchars(..., ENT_QUOTES, 'UTF-8') for HTML context; prefer templating with auto-escaping.",
  },
  {
    re: /echo\s+[^;]{0,500}(?:password|changed\s+to|new_pass)[^;]{0,200}\.\s*\$[a-zA-Z_]\w*/i,
    severity: "critical",
    title: "Sensitive value echoed to response (credential disclosure)",
    category: "Information disclosure",
    description:
      "Echoing passwords or secrets to the HTTP response leaks credentials to browsers, proxies, and logs — even for admins only.",
    fix: "Never echo secrets; confirm success with a generic message; log server-side only with redaction.",
  },
  {
    re: /=\s*["']0e\d{10,}["']/i,
    severity: "high",
    title: "PHP magic-hash style literal (0e + many digits)",
    category: "Authentication / type juggling",
    description:
      "Assigning a string like 0e123... is a common CTF/demo pattern paired with loose == comparisons against MD5 outputs; combined with == it can make unrelated hashes compare equal.",
    fix: "Remove magic-hash literals; use === and password_verify(); do not compare raw MD5 strings for auth.",
  },
];

/** Go / Golang — SQLi, SSRF, LFI, defer-in-loop (OWASP / CWE-aligned heuristics). */
const GO_DEEP_PATTERNS: Pattern[] = [
  {
    re: /\.(?:Query|QueryRow|Exec)\s*\(\s*fmt\.Sprintf\s*\(/,
    severity: "critical",
    title: "Go SQL injection: fmt.Sprintf inside db.Query/Exec/QueryRow",
    category: "SQL injection",
    description:
      "database/sql is safe with ? placeholders, but fmt.Sprintf builds raw SQL strings — classic SQLi if any part is untrusted.",
    fix: 'Use db.Query("SELECT … WHERE username = ?", username) with driver placeholders.',
  },
  {
    re: /(?:query|q)\s*:=\s*fmt\.Sprintf\s*\([^)]+\)[\s\S]{0,800}?\.(?:Query|QueryRow|Exec)\s*\(\s*(?:query|q)\b/,
    severity: "critical",
    title: "Go SQL: query built with fmt.Sprintf then passed to db.Query",
    category: "SQL injection",
    description: "Query variable assembled via Sprintf then executed — same class as string concat SQLi.",
    fix: "Parameterized queries only; never format SQL with user input.",
  },
  {
    re: /\bhttp\.Get\s*\(\s*targetURL\b|\bhttp\.Get\s*\(\s*r\.URL\.Query\(\)\.Get\s*\(/,
    severity: "critical",
    title: "Go SSRF: http.Get with obvious request-derived URL",
    category: "SSRF",
    description: "Server fetches a URL from user/query input — can reach internal services or cloud metadata.",
    fix: "Allowlist schemes/hosts; block RFC1918; disable redirects or validate each hop; timeouts + size limits.",
  },
  {
    re: /\bhttp\.Post(?:Form)?\s*\(\s*[a-zA-Z_$][\w$]*\s*,/,
    severity: "medium",
    title: "Go http.Post with variable URL",
    category: "SSRF",
    description: "POST to a dynamic URL — may be SSRF if the URL comes from users; many codebases use safe internal URLs.",
    fix: "Validate URL; allowlist hosts; block private ranges — confirm data flow.",
  },
  {
    re: /for\s+[\s\S]{0,120}?\{[\s\S]{0,6000}?defer\s+\w+\.Close\s*\(\s*\)/,
    severity: "high",
    title: "Go: defer Close() inside for loop (resource exhaustion)",
    category: "Denial of service",
    description:
      "defer runs when the surrounding function returns, not each iteration — many files/sockets can stay open until the handler ends.",
    fix: "Close at end of loop body, or use func() { f, _ := os.Open(...); defer f.Close(); ... }() per iteration.",
  },
  {
    re: /\bhttp\.ServeFile\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)/,
    severity: "high",
    title: "http.ServeFile with dynamic path",
    category: "Path traversal",
    description: "Serving files from a user-influenced path can expose arbitrary files if not rooted/jailed.",
    fix: "Map to an allowlist under a fixed root; reject path traversal.",
  },
  {
    re: /["']\/var\/[^"']+["']\s*\+\s*\w+/,
    severity: "critical",
    title: "Go path traversal: /var/… prefix concatenated with variable",
    category: "Path traversal",
    description: "Appending user-controlled segments to a host path (e.g. log name) enables ../ escapes to sensitive files.",
    fix: "filepath.Clean, enforce basename, reject .., jail under a fixed root.",
  },
];

const RUST_DEEP_PATTERNS: Pattern[] = [
  {
    re: /Command::new\s*\(\s*["']sh["']\s*\)\s*\.arg\s*\(\s*["']-c["']\s*\)\s*\.arg\s*\(\s*format!\s*\(/,
    severity: "critical",
    title: "Rust: sh -c + format! (shell command injection)",
    category: "Command injection",
    description: "User-controlled fragments inside format! passed to sh -c allow ; | && and arbitrary commands.",
    fix: "Command::new(\"nslookup\").arg(target) (no shell); validate hostname/IP with a strict parser.",
  },
  {
    re: /Command::new\s*\(\s*["']sh["']\s*\)\s*\.arg\s*\(\s*["']-c["']\s*\)\s*\.arg\s*\(\s*(?!format!)/,
    severity: "high",
    title: "Rust: sh -c with string argument (command injection)",
    category: "Command injection",
    description: "Shell interprets metacharacters in the passed string.",
    fix: "Invoke the binary directly with .arg() per argv slot; no shell.",
  },
  {
    re: /\.arg\s*\(\s*format!\s*\(/,
    severity: "medium",
    title: "Rust Command::arg with format! (verify inputs)",
    category: "Command injection",
    description: "If format! includes untrusted data, shell-less argv can still be abused depending on callee.",
    fix: "Validate/sanitize; prefer fixed argv and strict allowlists.",
  },
  {
    re: /unsafe\s*\{[\s\S]{0,2000}?(?:\*ptr|ptr)\s*(?:\.offset\s*\(|\.add\s*\(|\.wrapping_offset\s*\()/,
    severity: "critical",
    title: "Rust unsafe: pointer offset/add without bounds proof",
    category: "Memory safety",
    description: "Arbitrary offset from as_ptr/as_mut_ptr can write past allocation — UB, crash, or exploitable corruption.",
    fix: "Avoid unsafe; use slice indexing, Vec::get, or checked pointer APIs with proven lengths.",
  },
  {
    re: /format!\s*\(\s*["'][^"']*\{\}[^"']*["']\s*,\s*\w+\s*\)[\s\S]{0,900}?fs::read_to_string\s*\(/,
    severity: "high",
    title: "Rust format! path then fs::read_to_string",
    category: "Path traversal",
    description: "Building a filesystem path with format! and a request-derived segment enables ../ escapes.",
    fix: "Jail paths: canonicalize under a root Path; reject ParentDir components; allowlist filenames.",
  },
];

const RUBY_DEEP_PATTERNS: Pattern[] = [
  {
    re: /\bMarshal\.load\s*\(\s*\w+/,
    severity: "critical",
    title: "Ruby Marshal.load on variable data",
    category: "Deserialization",
    description: "Marshal can execute attacker-controlled object graphs.",
    fix: "Use JSON or signed formats; never Marshal.load untrusted bytes.",
  },
  {
    re: /\.where\s*\(\s*"[^"]*#\{/,
    severity: "critical",
    title: "Rails SQL: string interpolation in where()",
    category: "SQL injection",
    description: "Double-quoted SQL with #{} embeds request data — classic ActiveRecord SQLi.",
    fix: "User.where(\"name = ?\", params[:search]) or where(name: params[:search]) with permitted columns.",
  },
  {
    re: /\.(?:update|create|update!|create!)\s*\(\s*params\s*\[\s*:/,
    severity: "critical",
    title: "Rails mass assignment: raw params[...] to update/create",
    category: "Broken access control",
    description: "Permits clients to set arbitrary columns (e.g. is_admin) unless strong params permit() restricts fields.",
    fix: "params.require(:user).permit(:name, :email) only; never pass raw params[:user] into the model.",
  },
  {
    re: /`[^`]*#\{/,
    severity: "high",
    title: "Ruby backticks with string interpolation (command injection)",
    category: "Command injection",
    description: "Kernel backticks run a shell; #{...} with user input allows command chaining.",
    fix: "Open3.capture2e with argv array, or shell: false-style APIs; validate hostnames strictly.",
  },
  {
    re: /\bsystem\s*\(\s*[^"'`\s#][^)]*\)|\bexec\s*\(\s*[^"'`\s#][^)]*\)/,
    severity: "high",
    title: "Ruby system/exec with dynamic argument",
    category: "Command injection",
    description: "If the string includes user input, commands can be injected.",
    fix: "Use system(\"cmd\", \"arg1\", \"arg2\") array form or Open3 with argv.",
  },
];

const CSHARP_DEEP_PATTERNS: Pattern[] = [
  {
    re: /new\s+SqlCommand\s*\(\s*["'][^"']*["']\s*\+/,
    severity: "critical",
    title: "C# SqlCommand with string concatenation",
    category: "SQL injection",
    description: "Dynamic SQL built with + against user data.",
    fix: "Use parameters: command.Parameters.AddWithValue(...).",
  },
  {
    re: /string\s+\w+\s*=\s*"[^"]*"\s*\+\s*\w+[\s\S]{0,800}?new\s+SqlCommand\s*\(\s*\w+\s*,/i,
    severity: "critical",
    title: "C# ADO.NET: SQL built with + then SqlCommand(query, …)",
    category: "SQL injection",
    description: "Query text assembled with string concatenation and passed to SqlCommand — classic ADO.NET SQLi.",
    fix: "Parameterized SQL only: command.Parameters.AddWithValue(\"@u\", username); or EF Core.",
  },
  {
    re: /TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto)\b/,
    severity: "critical",
    title: "Newtonsoft.Json TypeNameHandling.All / Auto",
    category: "Deserialization",
    description: "Polymorphic $type in JSON can instantiate arbitrary types (gadget chains → RCE).",
    fix: "Use TypeNameHandling.None, System.Text.Json, or a strict SerializationBinder allowlist — never All/Auto on untrusted input.",
  },
  {
    re: /process\.StartInfo\.Arguments\s*=\s*[^;\n]+\+\s*\w+/i,
    severity: "high",
    title: "C# ProcessStartInfo.Arguments string concatenation",
    category: "Command injection",
    description: "Especially with cmd.exe /c, shell metacharacters (&, |) in user input run extra commands.",
    fix: "Prefer ProcessStartInfo.ArgumentList entries, invoke ping.exe directly, or System.Net.NetworkInformation.Ping; validate IP/hostname.",
  },
  {
    re: /(?:ConnectionString|DbConnectionString)\b[^=]*=\s*["'][^"']*\bPassword\s*=\s*[^;"']+/i,
    severity: "critical",
    title: "C# hardcoded DB connection string (embedded password)",
    category: "Secrets",
    description: "Connection strings with Password= in source expose database credentials.",
    fix: "User Secrets, environment variables, or a vault (e.g. Azure Key Vault); never commit sa/passwords.",
  },
  {
    re: /=\s*@?["'][^"'+\n]{0,260}["']\s*\+\s*\w+\s*;[\s\S]{0,650}?\.ReadAllText\s*\(\s*\w+\s*\)/i,
    severity: "high",
    title: "C# path concatenation before File.ReadAllText",
    category: "Path traversal",
    description: "Base path + user segment without jail checks allows ..\\ / ../ escapes.",
    fix: "Path.GetFullPath(Path.Combine(baseDir, name)) then verify the result is under baseDir; reject traversal.",
  },
  {
    re: /BinaryFormatter|NetDataContractSerializer/,
    severity: "critical",
    title: "Dangerous .NET deserialization API",
    category: "Deserialization",
    description: "BinaryFormatter and similar are unsafe on untrusted input.",
    fix: "Use System.Text.Json or DataContractSerializer with strict types.",
  },
];

const JAVA_DEEP_EXTRA: Pattern[] = [
  {
    re: /\.createQuery\s*\(\s*["'][^"']*["']\s*\+/,
    severity: "critical",
    title: "Java/JPA: dynamic query string concatenation",
    category: "SQL injection",
    description: "JPQL/SQL built by concatenating user fragments.",
    fix: "Named parameters / criteria API.",
  },
  {
    re: /InitialContext\s*\(\s*\)\s*\.lookup\s*\(\s*\w+\s*\)/,
    severity: "high",
    title: "JNDI lookup with variable (injection class)",
    category: "Injection",
    description: "Untrusted JNDI names can lead to remote class loading (Log4Shell class of bugs).",
    fix: "Allowlist JNDI names; disable remote class loading; validate input.",
  },
];

/** Spring / Jakarta EE-style patterns (XXE, mass assignment, NIO path traversal, weak crypto). */
const JAVA_SPRING_DEEP_PATTERNS: Pattern[] = [
  {
    re: /DocumentBuilderFactory\s*\.\s*newInstance\s*\(\)(?![\s\S]{0,8000}?disallow-doctype-decl)[\s\S]{0,6000}?newDocumentBuilder\s*\(\s*\)[\s\S]{0,4000}?\.\s*parse\s*\(/i,
    severity: "critical",
    title: "Java XXE: DOM DocumentBuilder parses XML without doctype/XXE hardening",
    category: "XML / XXE",
    description:
      "Default DocumentBuilderFactory often resolves DTDs and external entities — attackers can read files (file://), SSRF internal URLs, or cause DoS via billion laughs.",
    fix: 'Set factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true), FEATURE_SECURE_PROCESSING, and restrict ACCESS_EXTERNAL_DTD / SCHEMA / STYLESHEET.',
  },
  {
    re: /@ModelAttribute(?:\s*\([^)]*\))?\s+(?!String\b|Integer\b|Long\b|Boolean\b|Byte\b|Short\b|Character\b|Double\b|Float\b|int\b|long\b|boolean\b|byte\b|short\b|char\b|double\b|float\b|void\b|MultipartFile\b|Map\b|List\b|Set\b|Optional\b|HttpEntity\b|ResponseEntity\b|UriComponents\b|Locale\b|Principal\b|BindingResult\b|Errors?\b)([A-Z][a-zA-Z0-9_]*)\s+\w+/,
    severity: "critical",
    title: "Spring mass assignment: @ModelAttribute binds request to domain/entity type",
    category: "Broken access control",
    description:
      "Spring maps query/form fields to object setters. Hidden fields like isAdmin=true can elevate privileges (overposting). Never bind HTTP input directly to persistence entities.",
    fix: "Use a DTO with only allowed fields + explicit mapping; use @InitBinder allowlist or records with validation; never expose role/flag setters from raw requests.",
  },
  {
    re: /@RequestBody\s+(?!String\b|Integer\b|Long\b|Boolean\b|Byte\b|Short\b|int\b|long\b|boolean\b|byte\b|short\b|double\b|float\b|MultipartFile\b|Map\b|List\b|Set\b|Optional\b|HttpEntity\b|ResponseEntity\b|JsonNode\b|JsonObject\b|byte\[\]\s)([A-Z][a-zA-Z0-9_]*)\s+\w+/,
    severity: "high",
    title: "Spring @RequestBody binding to mutable object type (mass assignment)",
    category: "Broken access control",
    description:
      "JSON/XML bodies deserialize into full objects; clients can supply unexpected properties (e.g. role flags) unless you use DTOs, @JsonIgnoreProperties(ignoreUnknown=true) with tight types, or schema validation.",
    fix: "Prefer immutable DTOs, @JsonView, or OpenAPI-validated payloads; do not deserialize into JPA entities from the wire.",
  },
  {
    re: /Files\.readAllBytes\s*\(\s*Paths\.get\s*\([^)]*\+\s*[a-zA-Z_$][\w$]*\s*\)/,
    severity: "critical",
    title: "Java path traversal: Files.readAllBytes(Paths.get(prefix + user input))",
    category: "Path traversal",
    description:
      "Concatenating a fixed directory with a request parameter allows ../ segments to escape the intended folder (e.g. /etc/passwd).",
    fix: "Use Path.resolve, normalize, and verify path.startsWith(baseDir); reject ..; use UUID filenames server-side.",
  },
  {
    re: /Paths\.get\s*\(\s*["'][^"']+["']\s*\+\s*[a-zA-Z_$][\w$]*\s*\)/,
    severity: "critical",
    title: "Java path traversal: Paths.get(literal prefix + variable)",
    category: "Path traversal",
    description: "User-controlled filename appended to a path string — classic directory traversal.",
    fix: "Resolve under a jail directory; validate basename; block path separators and ..",
  },
  {
    re: /Cipher\.getInstance\s*\(\s*["'][^"']*\/ECB[^"']*["']\s*\)/i,
    severity: "critical",
    title: "Weak Java crypto: block cipher in ECB mode",
    category: "Crypto",
    description:
      "ECB is deterministic — identical plaintext blocks yield identical ciphertext (pattern leakage). Not suitable for general confidentiality.",
    fix: "Use AES/GCM/NoPadding (or ChaCha20-Poly1305) with a random IV/nonce per encryption.",
  },
  {
    re: /new\s+SecretKeySpec\s*\(\s*["'][^"']{4,}["']\s*\.\s*getBytes\s*\(/,
    severity: "critical",
    title: "Java crypto: SecretKeySpec from string literal .getBytes()",
    category: "Crypto",
    description: "Deriving AES keys from string literals in code is extractable from the binary or repo.",
    fix: "Load keys from KMS/HSM or environment; never embed raw key strings.",
  },
  {
    re: /new\s+SecretKeySpec\s*\(\s*[A-Z][A-Z0-9_]*\s*\.\s*getBytes\s*\(/,
    severity: "high",
    title: "Java crypto: SecretKeySpec(ConstantName.getBytes())",
    category: "Crypto",
    description: "Key material flows from a named constant — often defined as a hardcoded static final string nearby.",
    fix: "Use key vault / sealed secrets; pair with rotation policy.",
  },
];

/** C / C++ — memory safety, format strings, UAF heuristics (regex-only; use Cppcheck/CodeQL for precision). */
const C_CPP_DEEP_PATTERNS: Pattern[] = [
  {
    re: /\bstrcpy\s*\(\s*[a-zA-Z_][\w]*\s*,\s*(?:[a-zA-Z_][\w]*|argv\s*\[\s*[^\]]+\])\s*\)/,
    severity: "critical",
    title: "C/C++: strcpy() into fixed buffer (stack/heap overflow)",
    category: "Memory corruption",
    description:
      "strcpy does not bound the copy; attacker-controlled source can overflow the destination (RCE via return address overwrite on stack).",
    fix: "Use strncpy, strlcpy, or memcpy with min(sizeof(dest)-1, strlen(src)); prefer snprintf / safe string APIs.",
  },
  {
    re: /\bstrcat\s*\(\s*[a-zA-Z_][\w]*\s*,\s*(?:[a-zA-Z_][\w]*|argv\s*\[\s*[^\]]+\])\s*\)/,
    severity: "critical",
    title: "C/C++: strcat() unbounded append",
    category: "Memory corruption",
    description: "strcat does not check remaining space in the destination buffer.",
    fix: "Use strncat with bounds, or snprintf into a fresh buffer.",
  },
  {
    re: /\bsprintf\s*\(\s*[a-zA-Z_][\w]*\s*,\s*[a-zA-Z_][\w]*\s*,/,
    severity: "critical",
    title: "C/C++: sprintf() with variable format string (2nd argument)",
    category: "Memory corruption",
    description:
      "Second argument is the format string; if it is a variable (not a literal), attackers can inject format specifiers; buffer may still overflow without snprintf.",
    fix: "Use snprintf(dest, sizeof(dest), \"fixed\", ...); never pass user-controlled format strings.",
  },
  {
    re: /\bgets\s*\(/,
    severity: "critical",
    title: "C/C++: gets() is unsafe (removed in C11)",
    category: "Memory corruption",
    description: "gets cannot limit input length — always overflow-prone.",
    fix: "Use fgets or getline with explicit size.",
  },
  {
    re: /\bscanf\s*\(\s*["'][^"']*%s[^"']*["']/,
    severity: "high",
    title: "C/C++: scanf %s without field width",
    category: "Memory corruption",
    description: "Unbounded %s into a stack buffer is equivalent to a strcpy overflow.",
    fix: "Use %255s style width limits, or fgets + sscanf.",
  },
  {
    re: /\bprintf\s*\(\s*[a-zA-Z_][\w]*\s*(?:\)|,)/,
    severity: "critical",
    title: "C/C++: format string bug (user-controlled printf format)",
    category: "Format string",
    description:
      "When the first argument to printf is attacker-controlled, %x/%n and friends can leak memory or write arbitrary addresses.",
    fix: 'Always use printf(\"%s\", user_buf); fputs(user_buf, stdout) for untrusted data.',
  },
  {
    re: /\bfprintf\s*\(\s*[a-zA-Z_][\w]*\s*,\s*[a-zA-Z_][\w]*\s*,/,
    severity: "critical",
    title: "C/C++: fprintf with variable format string",
    category: "Format string",
    description: "Second argument is the format; if it is user-controlled, same impact as printf.",
    fix: "Use a fixed format string; pass user data only as values.",
  },
  {
    re: /free\s*\(\s*([a-zA-Z_]\w*)\s*\)\s*;[\s\S]{0,4000}?\bprintf\s*\([^)]*\b\1\b[^)]*\)/,
    severity: "critical",
    title: "C/C++: use-after-free (dangling pointer passed to printf)",
    category: "Memory safety",
    description:
      "free() does not clear the pointer; subsequent printf(..., ptr, ...) reads freed memory (undefined behavior, exploitable).",
    fix: "Set pointer to NULL immediately after free; do not use the pointer again.",
  },
  {
    re: /free\s*\(\s*([a-zA-Z_]\w*)\s*\)\s*;[\s\S]{0,4000}?\bif\s*\(\s*\1\s*!=\s*NULL\s*\)/,
    severity: "critical",
    title: "C/C++: use-after-free risk (pointer non-NULL check after free)",
    category: "Memory safety",
    description:
      "After free(), the pointer is dangling; comparing to NULL is misleading because free does not assign NULL — later use is UAF.",
    fix: "Assign NULL after free: free(p); p = NULL;",
  },
  {
    re: /\b(?:unsigned\s+)?(?:int|long|long\s+long|short|size_t)\s+\w+\s*=\s*\w+\s*\*\s*\d+/,
    severity: "high",
    title: "C/C++: integer overflow risk (multiply then allocate)",
    category: "Integer overflow",
    description:
      "Product of user-influenced count and element size can wrap in unsigned/fixed-width types; malloc gets a small buffer while logic writes more.",
    fix: "Check with __builtin_mul_overflow, sized helpers, or uintmax_t + explicit range checks before malloc.",
  },
  {
    re: /#define\s+\w*(?:SECRET|PASSWORD|PASS|KEY|TOKEN|ADMIN)\w*\s+"[^"]{3,}"/i,
    severity: "critical",
    title: "C/C++: hardcoded secret in #define",
    category: "Secrets",
    description: "Credentials embedded in preprocessor macros are visible in binaries and source.",
    fix: "Load secrets at runtime from a vault or secure env; rotate if exposed.",
  },
];

const SOLIDITY_DEEP_PATTERNS: Pattern[] = [
  {
    re: /\.call\s*\{\s*value:\s*[^}]+\}\s*\([^)]*\)[\s\S]{0,2200}?\bbalances\s*\[[^\]]+\]\s*=\s*0/,
    severity: "critical",
    title: "Solidity: external call before balance zeroed (reentrancy pattern)",
    category: "Reentrancy",
    description: "Ether/token transfer before state update lets a malicious contract re-enter withdraw and drain funds (Checks-Effects-Interactions violated).",
    fix: "Update balances first (effects), then external call (interactions); use ReentrancyGuard; pull over push where possible.",
  },
  {
    re: /\brequire\s*\(\s*tx\.origin\s*==/,
    severity: "high",
    title: "Solidity: tx.origin used for authorization",
    category: "Access control",
    description: "tx.origin is the transaction origin, not the immediate caller — phishing contracts can trick the owner and pass the check.",
    fix: "Use msg.sender for access control; document delegate-call implications separately.",
  },
];

const YAML_CI_PATTERNS: Pattern[] = [
  {
    re: /\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|head_ref|comment\.body|review\.body)\s*\}\}/,
    severity: "critical",
    title: "GitHub Actions: untrusted context in workflow (script injection)",
    category: "CI/CD injection",
    description: "Embedding attacker-controlled issue/PR title, body, or head_ref into run: scripts can break quoting and execute arbitrary bash on the runner.",
    fix: "Bind to env: TITLE: ${{ github.event.issue.title }} then run: echo \"$TITLE\"; or use action with audited string handling (see GitHub security hardening).",
  },
  {
    re: /password\s*:\s*['"][^$][^'"]{4,}['"]|apiKey\s*:\s*['"][^$][^'"]{4,}['"]/i,
    severity: "high",
    title: "YAML: possible hardcoded secret",
    category: "Secrets",
    description: "Literal secret-like value in YAML (not ${{ secrets.* }}).",
    fix: "Use ${{ secrets.NAME }} or external secret manager.",
  },
];

const SHELL_DEEP_PATTERNS: Pattern[] = [
  {
    re: /\beval\s+\$|\beval\s+["'`]/,
    severity: "critical",
    title: "Shell eval on variables or strings",
    category: "Command injection",
    description: "eval executes arbitrary shell code.",
    fix: "Avoid eval; use functions and quoted variables.",
  },
  {
    re: /curl\s+[^;|&]*\$\{?\w+\}?|wget\s+[^;|&]*\$\{?\w+\}?/,
    severity: "medium",
    title: "curl/wget with variable URL (SSRF / injection)",
    category: "SSRF",
    description: "URL built from shell variables can be attacker-influenced.",
    fix: "Validate URL; quote variables; allowlist hosts.",
  },
];

const SQL_DIALECT_PATTERNS: Pattern[] = [
  {
    re: /\bEXEC\s*\(\s*@\w+\s*\)|EXECUTE\s+IMMEDIATE\s+/i,
    severity: "critical",
    title: "Dynamic SQL EXEC / EXECUTE IMMEDIATE",
    category: "SQL injection",
    description: "Executing SQL held in a variable is SQLi-prone if built from concatenation.",
    fix: "Parameterized dynamic SQL only; avoid string-built EXEC.",
  },
];

/** `<a target="_blank">` without rel=noopener|noreferrer — reverse tabnabbing (window.opener). */
function collectReverseTabnabbingFindings(code: string): CodeFinding[] {
  const out: CodeFinding[] = [];
  const re = /<a\b[\s\S]{0,4000}?\btarget\s*=\s*["']_blank["'][\s\S]{0,2000}?>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const chunk = m[0];
    if (/noopener|noreferrer/i.test(chunk)) continue;
    out.push({
      severity: "medium",
      title: "Reverse tabnabbing: target=_blank without rel noopener/noreferrer",
      category: "Phishing / tab abuse",
      description:
        "New tabs opened with target=_blank can access window.opener and redirect the opener unless rel blocks it.",
      line: lineFromIndex(code, m.index),
      fix: 'Use rel="noopener noreferrer" on external links, or rel="noopener" as minimum.',
      source: "sast",
    });
    if (m[0].length === 0) re.lastIndex++;
  }
  return out;
}

/**
 * JWT present in file but DELETE/PUT/PATCH registers /api/... with only two arguments (path + handler).
 * May false-positive if auth runs inside the handler - verify manually.
 */
function collectExpressAuthGapFindings(code: string): CodeFinding[] {
  const out: CodeFinding[] = [];
  if (!/jwt\.sign|JWT_SECRET|jsonwebtoken/i.test(code)) return out;
  const re =
    /app\.(delete|put|patch)\s*\(\s*(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s*,\s*(?:async\s*)?\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const pathMatch = m[0].match(/['"]([^'"]+)['"]/);
    const path = pathMatch ? pathMatch[1] : "";
    if (!path.includes("/api/")) {
      if (m[0].length === 0) re.lastIndex++;
      continue;
    }
    out.push({
      severity: "high",
      title: "Sensitive HTTP verb on /api without visible auth middleware",
      category: "Broken access control",
      description: `${m[1].toUpperCase()} ${path} is registered with only a path and handler. If JWT/session checks are not enforced inside the handler, the route may be world-accessible.`,
      line: lineFromIndex(code, m.index),
      fix: "Add shared middleware (e.g. verify JWT) before the handler, or enforce authorization at the start of the handler for every method.",
      source: "sast",
    });
    if (m[0].length === 0) re.lastIndex++;
  }
  return out;
}

function lineFromIndex(code: string, index: number): number {
  return code.slice(0, index).split("\n").length;
}

/** Reduce false positives on secret-shaped assignments that clearly pull from env or templates. */
function isLikelyNonSecretLiteralLine(line: string): boolean {
  const t = line.toLowerCase();
  return (
    /\b(?:getenv|environ|os\.environ|process\.env|import\.meta\.env)\b/.test(line) ||
    /\$\{\{[^}]+\}\}/.test(line) ||
    /\b(?:redacted|changeme|your_[\w]*here|placeholder|lorem|dummy|test@|example\.org|example\.com)\b/i.test(line) ||
    /x{8,}/i.test(line) ||
    /password\s*[:=]\s*["']\*+["']/.test(t) ||
    /secret\s*[:=]\s*["']["']/.test(t)
  );
}

/** Math.random() is normal for UI; skip when the line looks visualisation/layout-only. */
function isLikelyUiMathRandomLine(line: string): boolean {
  return /\b(?:rgba?\(|hsl\(|gradient|pixel|opacity|chart|canvas|shuffle\(|\.sort\s*\(|animation|easing|layout|viewport|width|height|rotate|translate|jitter|noise|particle|Math\.floor\s*\(\s*Math\.random)/i.test(
    line,
  );
}

/** random.random() in notebooks / plots is usually benign. */
function isLikelyBenignPythonRandomLine(line: string): boolean {
  return /\b(?:plot|scatter|hist|sample|shuffle|numpy|np\.|pandas|pd\.|matplotlib|seaborn|torch|simulate|jitter)\b/i.test(
    line,
  );
}

/** `../` inside comments or doc examples should not fire path traversal. */
function isCommentStylePathTraversalLine(line: string): boolean {
  const t = line.trim();
  return /^(?:#|\/\/|\/\*|\*)/.test(t);
}

/** Lifecycle / disclosure patterns that line rules often miss. */
function collectResourceAndDisclosureFindings(code: string): CodeFinding[] {
  const out: CodeFinding[] = [];

  if (/sqlite3\.connect\s*\(/.test(code) && !/with\s+sqlite3\.connect/.test(code)) {
    const idx = code.search(/sqlite3\.connect\s*\(/);
    out.push({
      severity: "medium",
      title: "SQLite connection not using context manager",
      category: "Resource management",
      description:
        "sqlite3.connect() without `with sqlite3.connect(...) as conn` (or explicit close in finally) can leak connections and file handles under errors or load.",
      line: lineFromIndex(code, idx),
      fix: "Use `with sqlite3.connect(DB_PATH) as conn:` or try/finally with conn.close().",
      source: "sast",
    });
  }

  const openAssign = /^\s*(\w+)\s*=\s*open\s*\(/gm;
  let om: RegExpExecArray | null;
  while ((om = openAssign.exec(code)) !== null) {
    const lineStart = code.lastIndexOf("\n", om.index) + 1;
    const lineEnd = code.indexOf("\n", om.index);
    const lineText = code.slice(lineStart, lineEnd === -1 ? code.length : lineEnd);
    if (/^\s*#/.test(lineText)) continue;
    out.push({
      severity: "medium",
      title: "File opened without with statement",
      category: "Resource management",
      description:
        "open() without `with open(...) as f` or try/finally can leak file descriptors if an exception happens before close().",
      line: lineFromIndex(code, om.index),
      fix: "Use `with open(path, ...) as f:` or close in a finally block.",
      source: "sast",
    });
    if (om[0].length === 0) openAssign.lastIndex++;
  }

  const disclose = /except\s+Exception\s+as\s+(\w+)\s*:[\s\S]{0,1200}?print\s*\(\s*f["'][^"']*\{\s*\1\s*\}[^"']*["']/g;
  let dm: RegExpExecArray | null;
  while ((dm = disclose.exec(code)) !== null) {
    out.push({
      severity: "medium",
      title: "Exception details printed (information disclosure)",
      category: "Information disclosure",
      description:
        "Broad except blocks that print f-strings including the exception can expose SQL errors, file paths, or stack details to consoles or users.",
      line: lineFromIndex(code, dm.index),
      fix: "Log a generic message to a secure logger; never echo raw exception text to untrusted viewers.",
      source: "sast",
    });
    if (dm[0].length === 0) disclose.lastIndex++;
  }

  return out;
}

function collectPhpCsrfHints(code: string): CodeFinding[] {
  if (!/\$_POST/.test(code)) return [];
  if (/csrf|_token|__token|nonce|verify_csrf|SameSite/i.test(code)) return [];
  if (!/isset\s*\(\s*\$_POST/i.test(code)) return [];
  const sensitive =
    /\$_POST\s*\[\s*['"][^'"]*(?:password|login|new_password|logout|delete|upload|admin)/i.test(code) ||
    /isset\s*\(\s*\$_POST\s*\[\s*['"][^'"]*(?:password|login|new_password)/i.test(code);
  if (!sensitive) return [];
  const idx = code.search(/isset\s*\(\s*\$_POST/);
  if (idx < 0) return [];
  return [
    {
      severity: "medium",
      title: "State-changing POST without obvious CSRF token",
      category: "CSRF",
      description:
        "POST handlers that mutate sessions, passwords, or uploads should validate a per-session CSRF token (or equivalent) so other sites cannot submit cross-origin forms using the victim's cookies.",
      line: lineFromIndex(code, idx),
      fix: "Issue a random token per session; embed in forms; verify on POST with hash_equals(). Prefer SameSite cookies as defense in depth.",
      source: "sast",
    },
  ];
}

function tagsFromExplicitLanguage(language: unknown): Set<string> {
  const s = new Set<string>();
  if (typeof language !== "string") return s;
  const key = language.trim().toLowerCase().replace(/\s+/g, " ");
  const map: Record<string, string> = {
    go: "go",
    rust: "rust",
    ruby: "ruby",
    php: "php",
    java: "java",
    "c#": "csharp",
    csharp: "csharp",
    yaml: "yaml",
    shell: "shell",
    sql: "sql",
    javascript: "js",
    typescript: "js",
    python: "python",
    kotlin: "kotlin",
    swift: "swift",
    c: "c",
    "c++": "cpp",
    solidity: "solidity",
  };
  const tag = map[key];
  if (tag) s.add(tag);
  return s;
}

function inferLanguagesFromCode(code: string): Set<string> {
  const s = new Set<string>();
  /** Embedded SQL in Express/Node must not tag the paste as standalone SQL (fixes wrong AI + rule focus). */
  const looksLikeNodeJs =
    /\b(require\s*\(\s*['"]express['"]|require\s*\(\s*['"]child_process['"]|express\.Router|module\.exports\b|router\.(get|post|put|patch|delete)\s*\()/i.test(
      code,
    );
  if (/^\s*package\s+\w+/m.test(code)) s.add("go");
  if (/\bfn\s+main\s*\(\s*\)\s*\{|\buse\s+std::/m.test(code)) s.add("rust");
  if (/<\?php/i.test(code)) s.add("php");
  if (
    /^\s*import\s+java\./m.test(code) ||
    /^\s*import\s+javax\./m.test(code) ||
    /^\s*import\s+jakarta\./m.test(code) ||
    /^\s*import\s+org\.springframework\b/m.test(code) ||
    /\bpublic\s+static\s+void\s+main\s*\(/m.test(code) ||
    /\b(?:@RestController|@Controller|@SpringBootApplication|@RequestMapping|@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping)\b/.test(
      code,
    )
  ) {
    s.add("java");
  }
  if (/\busing\s+System\b|\bnamespace\s+[\w.]+\s*\{/m.test(code)) s.add("csharp");
  if (/\bimport\s+React\b|\bfrom\s+['"]react['"]/m.test(code)) s.add("js");
  if (looksLikeNodeJs) s.add("js");
  if (/\bactix_web::/.test(code)) s.add("rust");
  if (/\$\{\{\s*github\./.test(code) || (/^on:\s*$/m.test(code) && /\bjobs:\s*$/m.test(code))) s.add("yaml");
  if (/^\s*#!\/bin\/(ba)?sh\b/m.test(code)) s.add("shell");
  if (code.length < 12000 && /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b/i.test(code) && !looksLikeNodeJs) {
    s.add("sql");
  }
  if (/\bpragma\s+solidity\b/i.test(code)) s.add("solidity");
  if (/\bclass\s+\w+\s*<\s*ApplicationController\b/.test(code) || (/\bdef\s+\w+/m.test(code) && /\bparams\s*\[\s*:/.test(code)))
    s.add("ruby");
  if (/\b(?:require|gem)\s+['"][\w./-]+['"]/m.test(code) && /\bdef\s+\w+/m.test(code)) s.add("ruby");
  if (/^\s*(?:from\s+[\w.]+\s+)?import\s+[\w.]+/m.test(code) && /\bdef\s+\w+\s*\(/m.test(code)) s.add("python");
  if (/^\s*#\s*include\s*</m.test(code)) {
    s.add("c");
    if (/\b(?:class|template|namespace|std::|using\s+namespace|::\s*~?\w+\s*\(|public:|private:|protected:)\b/.test(code)) {
      s.add("cpp");
    }
  }
  return s;
}

/** Strong hint for Gemini when the user leaves language on Auto-detect (avoids "this is SQL" on Node snippets). */
export function inferPrimaryLanguageForPrompt(code: string, explicit: unknown): string {
  if (typeof explicit === "string") {
    const t = explicit.trim();
    if (t && t.toLowerCase() !== "auto-detect") return t;
  }
  if (
    /\brequire\s*\(\s*['"]express['"]|express\.Router|router\.(get|post|put|patch|delete)\s*\(|module\.exports\s*=/i.test(
      code,
    )
  ) {
    return "JavaScript (Node.js / Express). Embedded SQL inside string literals is still application code in this file—review SQL injection and command injection as Node server bugs, not as a standalone .sql script.";
  }
  if (/\brequire\s*\(\s*['"]child_process['"]|from\s+['"]child_process['"]/i.test(code)) {
    return "JavaScript or TypeScript on Node.js (uses child_process). Treat shell/exec risks as command injection in Node.";
  }
  if (/^\s*import\s+React\b|\bfrom\s+['"]react['"]/m.test(code)) {
    return "JavaScript or TypeScript (React). Focus on XSS, unsafe DOM, secrets in client bundles, and dependency risks.";
  }
  if (/^\s*(?:from\s+[\w.]+\s+)?import\s+[\w.]+/m.test(code) && /\bdef\s+\w+\s*\(/.test(code)) {
    return "Python.";
  }
  if (/^\s*package\s+\w+/m.test(code)) return "Go.";
  if (/<\?php/i.test(code)) return "PHP.";
  if (/^\s*import\s+java\./m.test(code)) return "Java.";
  return "Infer the main language from imports and syntax; embedded SQL strings in a larger file belong to that host language.";
}

function resolveLanguageTags(code: string, language: unknown): Set<string> {
  const L = typeof language === "string" ? language.trim().toLowerCase() : "";
  if (!L || L === "auto-detect") {
    return inferLanguagesFromCode(code);
  }
  const explicit = tagsFromExplicitLanguage(language);
  const inferred = inferLanguagesFromCode(code);
  return new Set([...explicit, ...inferred]);
}

function buildRecommendations(langs: Set<string>): string[] {
  const rec: string[] = [
    "Semgrep (open source, Apache-2.0): https://semgrep.dev — run `semgrep scan --config auto` on your repo for AST-based rules.",
    "CodeQL (open source): https://github.com/github/codeql-cli-binaries — deeper data-flow than Argus regex SAST.",
    "Add SonarQube or similar in CI if you need policy gates; Argus heuristics are not a compliance substitute.",
    "Enable dependency scanning (SCA): npm audit, pip-audit, go list -json -m all | nancy, OSV-Scanner.",
  ];
  if (langs.has("python")) rec.unshift("Python: pip install bandit && bandit -r .");
  if (langs.has("go")) rec.unshift("Go: go install github.com/securego/gosec/v2/cmd/gosec@latest && gosec ./...");
  if (langs.has("js"))
    rec.unshift("JavaScript/TypeScript: eslint-plugin-security, npm audit, and Retire.js for client libs.");
  if (langs.has("rust")) rec.push("Rust: cargo audit; review all unsafe { } blocks manually.");
  if (langs.has("java")) rec.push("Java: SpotBugs + FindSecBugs, or CodeQL Java queries.");
  if (langs.has("csharp")) rec.push("C#: Security Code Scan (Roslyn) or SonarAnalyzer security rules.");
  if (langs.has("ruby")) rec.push("Ruby on Rails: brakeman; avoid Kernel#open with dynamic URLs.");
  if (langs.has("php")) rec.push("PHP: Psalm/Psalm security plugin or PHPCS security sniffs.");
  if (langs.has("yaml")) rec.push("CI/CD: validate GitHub Actions against script-injection guidance (OWASP).");
  if (langs.has("shell")) rec.push("Shell: shellcheck; avoid eval and unquoted variables.");
  if (langs.has("sql")) rec.push("SQL: prefer stored procedures with parameters; never concat user input into EXEC().");
  if (langs.has("c") || langs.has("cpp")) {
    rec.push(
      "C/C++: run cppcheck --enable=all and consider CodeQL for C/C++; regex SAST cannot model pointer state.",
    );
  }
  if (langs.has("solidity")) rec.push("Solidity: slither . and Foundry/Echidna for reentrancy; avoid tx.origin for auth.");
  return [...new Set(rec)].slice(0, 15);
}

function collectDeepFindings(code: string, langs: Set<string>): CodeFinding[] {
  const out: CodeFinding[] = [];
  const pools: Pattern[] = [...DEEP_PATTERNS, ...NODE_AND_EXPRESS_DEEP_PATTERNS, ...PHP_DEEP_PATTERNS];
  if (langs.has("go")) pools.push(...GO_DEEP_PATTERNS);
  if (langs.has("rust")) pools.push(...RUST_DEEP_PATTERNS);
  if (langs.has("ruby")) pools.push(...RUBY_DEEP_PATTERNS);
  if (langs.has("csharp")) pools.push(...CSHARP_DEEP_PATTERNS);
  if (langs.has("java")) pools.push(...JAVA_DEEP_EXTRA, ...JAVA_SPRING_DEEP_PATTERNS);
  if (langs.has("yaml")) pools.push(...YAML_CI_PATTERNS);
  if (langs.has("shell")) pools.push(...SHELL_DEEP_PATTERNS);
  if (langs.has("sql")) pools.push(...SQL_DIALECT_PATTERNS);
  if (langs.has("c") || langs.has("cpp")) pools.push(...C_CPP_DEEP_PATTERNS);
  if (langs.has("solidity")) pools.push(...SOLIDITY_DEEP_PATTERNS);

  for (const p of pools) {
    const flags = p.re.flags.includes("g") ? p.re.flags : `${p.re.flags}g`;
    const r = new RegExp(p.re.source, flags);
    let m: RegExpExecArray | null;
    while ((m = r.exec(code)) !== null) {
      const line = lineFromIndex(code, m.index);
      out.push({
        severity: p.severity,
        title: p.title,
        description: p.description,
        line,
        category: p.category,
        fix: p.fix,
        source: "sast",
      });
      if (m[0].length === 0) r.lastIndex++;
    }
  }
  return out;
}

function riskRank(r: CodeReviewResult["overallRisk"]): number {
  return { critical: 5, high: 4, medium: 3, low: 2, safe: 1 }[r] ?? 0;
}

function worseRisk(a: CodeReviewResult["overallRisk"], b: CodeReviewResult["overallRisk"]) {
  return riskRank(a) >= riskRank(b) ? a : b;
}

export function runSastStaticScan(code: string, language?: unknown, extraFindings?: CodeFinding[]): CodeReviewResult {
  const langTags = resolveLanguageTags(code, language);
  const findings: CodeFinding[] = [];
  if (extraFindings?.length) {
    for (const f of extraFindings) findings.push({ ...f });
  }
  const lines = code.split("\n");
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    for (const p of PATTERNS) {
      if (!p.re.test(line)) continue;
      if (p.title === "Possible hardcoded secret" && isLikelyNonSecretLiteralLine(line)) continue;
      if (p.title === "Path traversal sequence" && isCommentStylePathTraversalLine(line)) continue;
      if (p.title === "Math.random for security context" && isLikelyUiMathRandomLine(line)) continue;
      if (p.title === "random.random for tokens" && isLikelyBenignPythonRandomLine(line)) continue;
      findings.push({
        severity: p.severity,
        title: p.title,
        description: p.description,
        line: li + 1,
        category: p.category,
        fix: p.fix,
        source: "sast",
      });
    }
  }

  findings.push(...collectDeepFindings(code, langTags));
  findings.push(...collectReverseTabnabbingFindings(code));
  findings.push(...collectResourceAndDisclosureFindings(code));
  findings.push(...collectExpressAuthGapFindings(code));
  findings.push(...collectPhpCsrfHints(code));

  const dedup = new Map<string, CodeFinding>();
  for (const f of findings) {
    const k = `${f.title}-${f.line ?? 0}-${f.category}`;
    if (!dedup.has(k)) dedup.set(k, f);
  }
  const uniq = [...dedup.values()].slice(0, 120);

  const withEvidence: CodeFinding[] = uniq.map((f) => ({
    ...f,
    evidence: f.evidence ?? (f.line != null ? lineEvidenceSnippet(code, f.line) : undefined),
  }));

  const critical = withEvidence.filter((f) => f.severity === "critical").length;
  const high = withEvidence.filter((f) => f.severity === "high").length;
  const medium = withEvidence.filter((f) => f.severity === "medium").length;
  const low = withEvidence.filter((f) => f.severity === "low").length;
  const info = withEvidence.filter((f) => f.severity === "info").length;

  let score: number;
  let overallRisk: CodeReviewResult["overallRisk"];

  if (withEvidence.length === 0) {
    /** No regex/Semgrep hits must not read as a high security grade — coverage is unknown. */
    score = 48;
    overallRisk = "low";
  } else {
    score = 100;
    score -= critical * 22 + high * 11 + medium * 6 + low * 2 + info;
    if (critical >= 2) score -= 10;
    if (critical >= 4) score -= 12;
    if (critical >= 6) score -= 10;
    score = Math.max(12, Math.min(98, score));

    if (critical > 0) overallRisk = "critical";
    else if (high >= 2) overallRisk = "high";
    else if (high === 1 || medium > 0) overallRisk = "medium";
    else if (low > 0) overallRisk = "low";
    else overallRisk = "safe";
  }

  return {
    overallRisk,
    score,
    findings: withEvidence,
    summary:
      withEvidence.length === 0
        ? `Static scan: no heuristic matches (language hints: ${[...langTags].join(", ") || "generic"}). That does not mean the code is safe — Argus uses line/regex rules only. Confirm with Semgrep (https://semgrep.dev) or CodeQL.`
        : `Static scan: ${withEvidence.length} hit(s) from line rules + multiline patterns (and Semgrep if enabled). False positives possible — confirm data flow.`,
    recommendations: buildRecommendations(langTags),
    reviewSource: "sast",
  };
}

export function mergeSastWithAi(sast: CodeReviewResult, ai: CodeReviewResult): CodeReviewResult {
  const sf = sast.findings.map((f) => ({
    ...f,
    source: (f.source === "semgrep" ? "semgrep" : "sast") as "sast" | "semgrep",
  }));
  const af = ai.findings.map((f) => ({ ...f, source: "ai" as const }));
  const findings = [...sf, ...af];
  const score = Math.min(sast.score, ai.score);
  const overallRisk = worseRisk(sast.overallRisk, ai.overallRisk);
  const recs = [...new Set([...sast.recommendations, ...ai.recommendations])].slice(0, 15);
  return {
    overallRisk,
    score,
    findings,
    summary: `SAST (${sast.findings.length}): ${sast.summary} · AI (${ai.findings.length}): ${ai.summary}`,
    recommendations: recs,
    reviewSource: "sast+gemini",
    staticFindingsCount: sf.length,
    aiFindingsCount: af.length,
  };
}
