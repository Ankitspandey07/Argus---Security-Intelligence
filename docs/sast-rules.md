# Argus static (SAST) rules — maintainer reference

This document describes every heuristic rule in [`src/lib/sast-static-scan.ts`](../src/lib/sast-static-scan.ts). The scanner is **regex + multiline patterns only** (no AST, no data-flow). It complements optional AI review; it does **not** replace Semgrep, CodeQL, or language-native tools.

## Goals

| Goal | How we approach it |
|------|-------------------|
| **High recall** | Broad line rules + language-specific “deep” packs (Go, Node, PHP, etc.). |
| **Higher precision** | Line-level suppressions for obvious false-positive contexts (comments, `SafeLoader`, UI `Math.random`, env lookups). |
| **Maintainability** | One source of truth in TypeScript; this file stays in sync when you add or change rules. |

## How a scan runs

1. **Language tags** — `resolveLanguageTags(code, language)` merges:
   - **Explicit** dropdown value (`Go`, `Python`, …) → internal tag (`go`, `python`, …).
   - **Auto-detect** → `inferLanguagesFromCode` (heuristics: `package` → Go, `pragma solidity` → Solidity, `import React` / `from 'react'` → JS, `ApplicationController` / `params[:` → Ruby, `actix_web::` → Rust, …).
2. **Line scan** — Each line is tested against **`PATTERNS`** (see below). Some titles apply **context filters** (skip line if it looks like a placeholder, comment-only `..`, etc.).
3. **Deep scan** — Full paste is scanned with **`DEEP_PATTERNS`** + **`NODE_AND_EXPRESS_DEEP_PATTERNS`** + **`PHP_DEEP_PATTERNS`** + optional packs (**`GO_DEEP_PATTERNS`**, **`RUST_DEEP_PATTERNS`**, …) based on language tags.
4. **Collectors** — Extra logic: reverse tabnabbing (`<a target="_blank">` without `noopener`), Express JWT route gap, SQLite/`open()` lifecycle, PHP CSRF hint, Python exception printing.
5. **Dedup** — Key: `` `${title}-${line}-${category}` ``; max **120** findings.

## Language tags → deep rule packs

| Tag | Activated deep packs |
|-----|----------------------|
| `go` | `GO_DEEP_PATTERNS` |
| `rust` | `RUST_DEEP_PATTERNS` |
| `ruby` | `RUBY_DEEP_PATTERNS` |
| `csharp` | `CSHARP_DEEP_PATTERNS` |
| `java` | `JAVA_DEEP_EXTRA` + **`JAVA_SPRING_DEEP_PATTERNS`** |
| `yaml` | `YAML_CI_PATTERNS` |
| `shell` | `SHELL_DEEP_PATTERNS` |
| `sql` | `SQL_DIALECT_PATTERNS` |
| `js`, `python`, `php` | No *extra* pack beyond shared deep + line rules (Python/JS still hit `DEEP_PATTERNS`, Node rules, etc.). |
| `c` and/or `cpp` | **`C_CPP_DEEP_PATTERNS`** (see §L) |
| `solidity` | **`SOLIDITY_DEEP_PATTERNS`** |

`kotlin`, `swift` are tagged for recommendations only unless you add new packs.

**Path traversal line rule precision:** the `..\\` alternative uses `(?<!\.)\.\.\\` so we do **not** match the second and third dot of a C-string ellipsis plus the backslash of `\n` (which previously looked like `..\`).

---

## A. `PATTERNS` (line-by-line)

Each row is one rule. **Regex** columns are descriptive; see source for exact patterns.

### JavaScript / TypeScript / Node

| Title | Severity | Intent | Common FPs |
|-------|----------|--------|------------|
| `eval()` | high | Dynamic code execution | Rare |
| `new Function()` | high | Dynamic code compilation | Bundlers sometimes use static strings only — still review |
| `dangerouslySetInnerHTML` | medium | React XSS sink | Legitimate if sanitized |
| `innerHTML assignment` | medium | DOM XSS | Static HTML only is OK |
| `document.write` | low | Legacy XSS | Old pages |
| `setTimeout` / `setInterval` with string | medium | Implicit eval | Prefer function refs |
| `child_process.exec` / `execSync` | high | Shell metacharacters | |
| `spawn({ shell: true })` | high | Shell expansion | |
| `if (window.*` branch | medium | DOM clobbering / trusting globals | Rare in hardened apps |

### Python

| Title | Severity | Intent | Common FPs |
|-------|----------|--------|------------|
| `os.system()` | high | Shell | |
| `subprocess` with `shell=True` | high | Shell injection | |
| `pickle.load` | high | Unsafe deserialization | |
| `yaml.load` | high | Unsafe YAML | **Suppressed** when line contains `SafeLoader` / safe loader pattern |
| `marshal.load` | high | Unsafe deserialization | |
| `shelve.open` | medium | Pickle-based store | |

### SQL / SSRF / path (generic)

| Title | Severity | Intent | Common FPs |
|-------|----------|--------|------------|
| SQL + `+` with `req`/`request`/… | high | Concat SQLi | Test strings mentioning `req` |
| `../` / `..\\` / encoded traversal | medium | Traversal literals | **Skipped** on comment-only lines; **`..\\` requires `(?<!\.)\.\.`** so `"...\n"` is not a hit |
| HTTP client + request-derived URL | medium | SSRF hint | Noisy on well-validated code |

### Secrets & crypto

| Title | Severity | Intent | Common FPs |
|-------|----------|--------|------------|
| Possible hardcoded secret (`password=` …) | high | Literal secret-like names | **Skipped** when line suggests env/template/placeholder (see `isLikelyNonSecretLiteralLine` in source) |
| PEM private key block | critical | Key in paste | |
| AWS `AKIA*`-style | critical | Access key id | Demo strings still flagged (intentional) |
| Hardcoded `*Key`/`*Secret` const | critical | Credential const | |
| `ghp_` (20+ alnum), `github_pat_`, `sk_live_`, `pk_live_`, Slack `xox*` | critical / medium | Known token shapes; `pk_live_` is medium (publishable, not secret) |
| `md5` / `sha1` | low | Weak hash | Legitimate file checksums |
| `Math.random()` | medium | Non-crypto RNG | **Skipped** on lines that look UI/visualization-only (heuristic) |
| `random.random()` | medium | Non-crypto RNG | **Skipped** when `plot`/`shuffle`/`numpy`/`pandas` on line (heuristic) |

### PHP

| Title | Severity | Intent |
|-------|----------|--------|
| `mysql_` / `mysqli_query` + `$` | medium | Verify parameterization |
| `unserialize($` | high | Object injection |
| `include`/`require` + `$_` | critical | LFI |

### Java

| Title | Severity | Intent |
|-------|----------|--------|
| `Runtime.getRuntime().exec` | high | Command execution |
| `ObjectInputStream` / `readObject` | medium | Deserialization |

### Go (line rules)

| Title | Severity | Intent |
|-------|----------|--------|
| `exec.Command("sh"` … | high | Shell |
| `InsecureSkipVerify: true` | high | TLS MITM risk |
| `http.Get(` non-literal | critical | SSRF class |
| `os.ReadFile`/`ioutil.ReadFile` prefix `+` | critical | Path traversal class |

### Quality

| Title | Severity | Intent |
|-------|----------|--------|
| `debugger` | low | Left in prod |
| Security `TODO`/`FIXME` | info | Debt marker |

---

## B. `DEEP_PATTERNS` (full-text, multiline)

| Title | Severity | Category | Notes |
|-------|----------|----------|--------|
| `execute()` with `f"…"` / f'…' | critical | SQLi | Python |
| `execute()` with `%` SQL + `% (` | critical | SQLi | |
| f-string with SQL keywords + `{…}` | critical | SQLi | |
| `query = f"…{…}` | high | SQLi | |
| HTML `+` user-like symbols | critical | XSS | |
| **Narrowed:** `html`/`body`/`response`/… `+=` `+` var | medium | XSS | Reduced noise vs any `x +=` |
| `return` + `+` user-like | high | XSS | |
| `open("…"+ var)` | high | Path traversal | |
| Prefix `uploads`/`var/www`/… + var | high | Path traversal | |
| `%` SQL + later `.execute(query)` | critical | SQLi | |
| Mutable default `[]` in def args | medium | Logic | Bandit B006-style |
| Bare `except:` | medium | Reliability / security | |
| `ET.fromstring` | medium | XML/XXE hint | |
| `os.system`/`popen` + string `+` | high | Command injection | Python-specific fix (not applied to C#) |
| Django `.raw_query` / `.extra(where=` `{` | high | SQLi | |

---

## C. `NODE_AND_EXPRESS_DEEP_PATTERNS`

| Title | Severity | Category |
|-------|----------|----------|
| `findOne({ username, password })` from request scope | critical | NoSQLi |
| `axios.*(targetUrl` | critical | SSRF |
| `axios.*(req.body` | critical | SSRF |
| `fetch(targetUrl` / `fetch(req.body` | high | SSRF |
| `send`/`json` with `err.stack` | high | Info disclosure |
| `deleteOne({ _id: var })` without `ObjectId` | medium | IDOR / integrity |

---

## D. `PHP_DEEP_PATTERNS`

| Title | Severity | Category |
|-------|----------|----------|
| `md5($_GET…)` + loose `==` compare | critical | Type juggling |
| `include`/`require` `"…".$` | critical | LFI |
| `$_FILES` + `move_uploaded_file` (no validation in window) | critical | Upload RCE |
| `echo` + `$_GET` concat | high | XSS |
| `echo` password-like + `$` | critical | Credential leak |
| `0e` long digit literal | high | Magic hash demos |

---

## E. `GO_DEEP_PATTERNS`

| Title | Severity | Category |
|-------|----------|----------|
| `db.Query/Exec/QueryRow(fmt.Sprintf` | critical | SQLi |
| `query := fmt.Sprintf` → `db.Query(query)` | critical | SQLi |
| `http.Get(targetURL` / `r.URL.Query().Get` | critical | SSRF |
| `http.Post(Form)?(var,` — variable URL | medium | SSRF (broad; verify) |
| `for { … defer …Close()` | high | FD exhaustion |
| `http.ServeFile(w,r,var)` | high | Path traversal |
| `"/var/…"+var` | critical | Path traversal |

---

## F. `RUST_DEEP_PATTERNS`

| Title | Severity | Category |
|-------|----------|----------|
| `Command::new("sh").arg("-c").arg(format!` | critical | Shell + format! injection |
| `Command::new("sh").arg("-c").arg(` (not `format!`) | high | Command injection |
| `.arg(format!(…` | medium | Verify untrusted input in argv |
| `unsafe` + `ptr.offset` / `.add` | critical | Memory safety / OOB |
| `format!(…{}…)` → `fs::read_to_string` | high | Path traversal |

---

## G. `RUBY_DEEP_PATTERNS`

| Title | Severity | Category |
|-------|----------|----------|
| `Marshal.load(var` | critical | Deserialization |
| `.where("…#{` (double-quoted SQL + `#{`) | critical | ActiveRecord SQLi |
| `.update`/`.create` + `params[:…]` | critical | Mass assignment |
| backticks + `#{}` | high | Command injection |
| `system`/`exec` non-literal first arg | high | Command injection |

---

## H. `CSHARP_DEEP_PATTERNS` & `JAVA_DEEP_EXTRA`

| Title | Severity | Category |
|-------|----------|----------|
| `new SqlCommand("…" +` | critical | SQLi (C#) |
| `string q = "…SELECT…" + var` → `new SqlCommand(q,` | critical | SQLi (C# ADO.NET) |
| `TypeNameHandling.All` / `Auto` (Newtonsoft) | critical | Unsafe deserialization (C#) |
| `process.StartInfo.Arguments = … + var` | high | Command injection (C#) |
| `ConnectionString` / `DbConnectionString` with `Password=` | critical | Hardcoded secret (C#) |
| path `+` var → `.ReadAllText` | high | Path traversal (C#) |
| `BinaryFormatter` / `NetDataContractSerializer` | critical | Deserialization (C#) |
| `.createQuery("…" +` | critical | SQLi (Java/JPA) |
| `InitialContext().lookup(var` | high | JNDI injection class |

### H2. `JAVA_SPRING_DEEP_PATTERNS` (loaded when tag `java` is active)

Spring/Jakarta controllers are detected via `import java.*`, `javax.*`, `jakarta.*`, `org.springframework.*`, or annotations such as `@RestController`, `@GetMapping`, etc.

| Title | Severity | Category | What it catches |
|-------|----------|----------|-----------------|
| `DocumentBuilderFactory.newInstance` → `parse` without `disallow-doctype-decl` in window | critical | XML / XXE | Classic DOM XXE (`<!ENTITY xxe SYSTEM "file:///..."`) |
| `@ModelAttribute` + non-primitive type (not String/Map/List/…) | critical | Mass assignment / overposting | Binding HTTP params to entities (e.g. `isAdmin=true`) |
| `@RequestBody` + mutable object type | high | Mass assignment | JSON overposting into full objects |
| `Files.readAllBytes(Paths.get(… + var))` | critical | Path traversal | Prefix + user filename |
| `Paths.get("…" + var)` | critical | Path traversal | Literal path + variable |
| `Cipher.getInstance("…/ECB…")` | critical | Crypto | ECB mode leakage |
| `new SecretKeySpec("…".getBytes()` | critical | Crypto | Key from string literal |
| `new SecretKeySpec(CONST.getBytes()` | high | Crypto | Key from static constant |

**Limits:** Regex cannot prove Spring Security or DTOs are absent; confirm with FindSecBugs / CodeQL / Semgrep Spring rules.

---

## I. `YAML_CI_PATTERNS`

| Title | Severity | Category |
|-------|----------|----------|
| `${{ github.event.issue.title }}`, `issue.body`, `pull_request.title`, `head_ref`, etc. | critical | GitHub Actions script injection in `run:` |
| `password:` / `apiKey:` literal in YAML | high | Secrets in CI YAML |

---

## I2. `SOLIDITY_DEEP_PATTERNS`

| Title | Severity | Category |
|-------|----------|----------|
| `.call{value:…}` then later `balances[…] = 0` | critical | Reentrancy (effects after interaction) |
| `require(tx.origin ==` | high | Authorization via tx.origin (phishing) |

---

## J. `SHELL_DEEP_PATTERNS` & `SQL_DIALECT_PATTERNS`

| Title | Severity | Category |
|-------|----------|----------|
| `eval $` / `eval "` | critical | Shell injection |
| `curl`/`wget` + `$var` URL | medium | SSRF / injection |
| `EXEC(@dyn)` / `EXECUTE IMMEDIATE` | critical | Dynamic SQL |

---

## L. `C_CPP_DEEP_PATTERNS` (tag `c` and/or `cpp`)

Triggered when `#include <…>` appears (always adds **`c`**), and **`cpp`** is added if the paste looks like C++ (`class`, `namespace`, `std::`, etc.).

| Title | Severity | Category |
|-------|----------|----------|
| `strcpy(dest, src)` / `argv[n]` source | critical | Stack/heap overflow |
| `strcat` + identifier or `argv[…]` | critical | Buffer overflow |
| `sprintf(buf, fmt,` with variable `fmt` | critical | Format + overflow class |
| `gets(` | critical | Unbounded read |
| `scanf("…%s…")` without width | high | Overflow |
| `printf(var)` or `printf(var,` | critical | Format string |
| `fprintf(stream, fmt,` variable fmt | critical | Format string |
| `free(p);` … `printf(…, p, …)` | critical | Use-after-free |
| `free(p);` … `if (p != NULL)` | critical | UAF / dangling pointer |
| `unsigned int x = n * constant` | high | Integer overflow → heap smash |
| `#define …SECRET… "…"` | critical | Hardcoded secret |

**Limits:** No pointer aliasing, no buffer size model — recommend **Cppcheck** and **CodeQL** in `buildRecommendations`.

---

## K. Structural collectors (functions)

| Function | Behavior |
|----------|----------|
| `collectExpressAuthGapFindings` | If file mentions JWT/jsonwebtoken, flags `DELETE`/`PUT`/`PATCH` on `/api/…` registered with only path + handler (auth may still be inside handler — **manual verify**). |
| `collectResourceAndDisclosureFindings` | SQLite connect without `with`; Python `open()` without `with` heuristic; `except Exception as e` + `print(f"...{e}...")`. |
| `collectPhpCsrfHints` | `$_POST` + sensitive action without obvious CSRF/SameSite token. |

---

## Line-level precision helpers (source)

These run **after** a line matches a `PATTERNS` rule, to drop obvious false positives:

| Helper | Skips findings for |
|--------|-------------------|
| `isLikelyNonSecretLiteralLine` | “Possible hardcoded secret” when env/template/placeholder/redacted patterns present |
| `isCommentStylePathTraversalLine` | “Path traversal sequence” on `#`, `//`, `/*`, `*` comment lines |
| `isLikelyUiMathRandomLine` | “Math.random…” on UI/visualisation-heavy lines |
| `isLikelyBenignPythonRandomLine` | “random.random…” on plot/numpy/pandas-style lines |

## Adding or changing rules

1. **Prefer deep patterns** for order-sensitive or multi-line issues (Go `fmt.Sprintf` → `Query`).
2. **Keep line rules fast** — one regex test per line; avoid catastrophic backtracking (`{0,50000}`-style).
3. **Document here** — add a row to the right table and mention **FP mitigations** if you add context skips in code.
4. **Run tests** — `npm run build`; manually paste known-good and known-bad snippets in the Code Review UI.

## OWASP alignment (informal)

Rules map loosely to OWASP categories: **Injection**, **Broken Authentication**, **Sensitive Data Exposure**, **XXE**, **Broken Access Control**, **Security Misconfiguration**, **XSS**, **Insecure Deserialization**, **SSRF**. For methodology depth, see the [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/).

## Related files

- Implementation: [`src/lib/sast-static-scan.ts`](../src/lib/sast-static-scan.ts)
- Evidence snippets: [`src/lib/sast-evidence.ts`](../src/lib/sast-evidence.ts)
- API: [`src/app/api/code-review/route.ts`](../src/app/api/code-review/route.ts)
