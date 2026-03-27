"use client";
import { useState, useCallback } from "react";
import {
  KeyRound, Unlock, Wand2, ChevronRight, Layers, Link2, FileCode, Type, Binary, Globe, ExternalLink,
  Share2,
} from "lucide-react";
import { jsonHeadersWithArgus } from "@/lib/argus-client-headers";

type Mode =
  | "auto"
  | "jwt"
  | "base64"
  | "hex"
  | "url"
  | "url_shorten"
  | "base64url"
  | "html"
  | "rot13"
  | "unicode"
  | "binary"
  | "punycode";

interface AutoDet {
  method: string;
  confidence: string;
  result: Record<string, unknown>;
}

const MODES: { id: Mode; label: string; icon: typeof Wand2 }[] = [
  { id: "auto", label: "Auto", icon: Wand2 },
  { id: "jwt", label: "JWT", icon: KeyRound },
  { id: "base64", label: "Base64", icon: ChevronRight },
  { id: "base64url", label: "Base64url", icon: KeyRound },
  { id: "hex", label: "Hex", icon: Binary },
  { id: "url", label: "URL", icon: Link2 },
  { id: "url_shorten", label: "Short link", icon: Share2 },
  { id: "html", label: "HTML entities", icon: FileCode },
  { id: "rot13", label: "ROT13", icon: Type },
  { id: "unicode", label: "Unicode", icon: Type },
  { id: "binary", label: "Binary", icon: Binary },
  { id: "punycode", label: "IDN / Punycode", icon: Globe },
];

export default function DecodeTool() {
  const [input, setInput] = useState("");
  const [mode, setMode] = useState<Mode>("auto");
  const [direction, setDirection] = useState<"encode" | "decode">("decode");
  const [out, setOut] = useState<Record<string, unknown> | null>(null);
  const [autoList, setAutoList] = useState<AutoDet[]>([]);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const runAuto = useCallback(async () => {
    setErr("");
    setOut(null);
    setAutoList([]);
    if (!input.trim()) return;
    setLoading(true);
    try {
      const res = await fetch("/api/decode/auto", {
        method: "POST",
        headers: jsonHeadersWithArgus(),
        body: JSON.stringify({ raw: input }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Auto decode failed");
      setAutoList(Array.isArray(data.detections) ? data.detections : []);
      if (data.message && (!data.detections || data.detections.length === 0)) setErr(data.message);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : "Error");
    } finally {
      setLoading(false);
    }
  }, [input]);

  const runManual = async () => {
    setErr("");
    setOut(null);
    setAutoList([]);
    if (!input.trim()) return;
    setLoading(true);
    try {
      const t = input.trim();
      if (mode === "url_shorten") {
        const res = await fetch("/api/tools/shorten-url", {
          method: "POST",
          headers: jsonHeadersWithArgus(),
          body: JSON.stringify({ url: t }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(typeof data.error === "string" ? data.error : "Shorten failed");
        setOut(data);
        return;
      }
      const dir = mode === "jwt" || mode === "rot13" ? "decode" : direction;
      const body: Record<string, string> = { direction: dir };
      if (mode === "jwt") body.jwt = t;
      else if (mode === "base64") body.base64 = t;
      else if (mode === "hex") body.hex = t;
      else if (mode === "url") body.urlText = t;
      else if (mode === "base64url") body.base64url = t;
      else if (mode === "html") body.htmlEntities = t;
      else if (mode === "rot13") body.rot13 = t;
      else if (mode === "unicode") body.unicodeCodepoints = t;
      else if (mode === "binary") body.binary = t;
      else if (mode === "punycode") body.punycodeHost = t;

      const res = await fetch("/api/decode", {
        method: "POST",
        headers: jsonHeadersWithArgus(),
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Request failed");
      setOut(data);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : "Error");
    } finally {
      setLoading(false);
    }
  };

  const run = () => {
    if (mode === "auto") runAuto();
    else runManual();
  };

  const showDirection =
    mode !== "auto" && mode !== "jwt" && mode !== "rot13" && mode !== "url_shorten";

  return (
    <div className="bg-surface border border-border rounded-xl overflow-hidden h-full flex flex-col">
      <div className="p-4 border-b border-border flex items-start gap-3 shrink-0">
        <div className="w-10 h-10 rounded-lg bg-accent/15 flex items-center justify-center shrink-0">
          <Layers className="w-5 h-5 text-accent" />
        </div>
        <div>
          <h3 className="font-semibold text-white text-sm">Crypto / encoding lab</h3>
          <p className="text-[11px] text-text-dim mt-1 leading-relaxed">
            <span className="text-text-muted">Short link</span> uses is.gd / TinyURL via this app. For JWTs use the{" "}
            <span className="text-text-muted">JWT</span> tab (not Base64url). External JWT tools are linked below.
          </p>
        </div>
      </div>

      <div className="p-4 space-y-3 flex-1 flex flex-col min-h-0">
        <div className="flex flex-wrap gap-2">
          {MODES.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              onClick={() => {
                setMode(id);
                setErr("");
                setOut(null);
                setAutoList([]);
              }}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[11px] font-mono rounded-lg border transition-colors ${
                mode === id ? "border-accent text-accent bg-accent/10" : "border-border text-text-dim hover:text-white"
              }`}
            >
              <Icon className="w-3 h-3 shrink-0" />
              {label}
            </button>
          ))}
        </div>

        {showDirection && (
          <div className="flex rounded-lg border border-border overflow-hidden w-fit">
            <button
              type="button"
              onClick={() => setDirection("decode")}
              className={`px-3 py-1.5 text-xs font-semibold ${
                direction === "decode" ? "bg-accent text-white" : "bg-bg text-text-dim hover:text-white"
              }`}
            >
              Decode
            </button>
            <button
              type="button"
              onClick={() => setDirection("encode")}
              className={`px-3 py-1.5 text-xs font-semibold ${
                direction === "encode" ? "bg-accent text-white" : "bg-bg text-text-dim hover:text-white"
              }`}
            >
              Encode
            </button>
          </div>
        )}

        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          rows={8}
          placeholder={
            mode === "auto"
              ? "Paste anything: JWT, hex, Base64, URL-encoded…"
              : mode === "jwt"
                ? "eyJhbGciOiJIUzI1NiIs..."
                : mode === "base64"
                  ? direction === "encode"
                    ? "Hello world"
                    : "SGVsbG8gd29ybGQ="
                  : mode === "base64url"
                    ? direction === "encode"
                      ? "Hello world"
                      : "Zm9vYmFy"
                    : mode === "hex"
                      ? direction === "encode"
                        ? "ABC"
                        : "48656c6c6f"
                      : mode === "url"
                        ? direction === "encode"
                          ? "hello world"
                          : "hello%20world%2Btest"
                        : mode === "url_shorten"
                          ? "https://example.com/very/long/path"
                          : mode === "html"
                          ? direction === "encode"
                            ? "<div>\"x\"</div>"
                            : "&lt;div&gt;Tom &amp; Jerry&lt;/div&gt;"
                          : mode === "rot13"
                            ? "Uryyb jbeyq"
                            : mode === "unicode"
                              ? direction === "encode"
                                ? "Hello 世界"
                                : "U+0048 U+0065"
                              : mode === "binary"
                                ? direction === "encode"
                                  ? "Hi"
                                  : "01001000 01101001"
                                : mode === "punycode"
                                  ? direction === "encode"
                                    ? "münchen.de"
                                    : "xn--mnchen-3ya.de"
                                  : "…"
          }
          className="w-full flex-1 min-h-[140px] bg-bg border border-border rounded-lg p-3 font-mono text-xs text-text resize-y focus:outline-none focus:border-accent"
          spellCheck={false}
        />

        <button
          type="button"
          onClick={run}
          disabled={loading || !input.trim()}
          className="inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-accent hover:bg-accent-hover text-white text-sm font-semibold rounded-lg disabled:opacity-40 shrink-0"
        >
          <Unlock className="w-4 h-4" />
          {loading
            ? "Running…"
            : mode === "auto"
              ? "Run auto detect"
              : mode === "url_shorten"
                ? "Create short link"
                : direction === "encode"
                  ? "Encode"
                  : "Decode"}
        </button>

        {err && <p className="text-xs text-warning shrink-0">{err}</p>}

        {mode === "auto" && autoList.length > 0 && (
          <div className="space-y-3 flex-1 min-h-0 overflow-y-auto">
            {autoList.map((d, i) => (
              <div key={i} className="rounded-lg border border-border bg-bg/80 overflow-hidden">
                <div className="px-3 py-2 bg-surface-2/80 border-b border-border flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-white">{d.method}</span>
                  <span className="text-[10px] font-mono uppercase text-accent">{d.confidence} confidence</span>
                </div>
                <pre className="text-[11px] font-mono text-text-muted p-3 overflow-x-auto whitespace-pre-wrap break-all">
                  {JSON.stringify(d.result, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        )}

        {mode !== "auto" && out && (
          <pre className="text-[11px] font-mono text-text-muted bg-bg border border-border rounded-lg p-3 overflow-x-auto max-h-80 overflow-y-auto shrink-0">
            {JSON.stringify(out, null, 2)}
          </pre>
        )}

        <div className="mt-auto pt-4 border-t border-border space-y-2 shrink-0">
          <p className="text-[10px] uppercase tracking-wider text-text-dim font-semibold">External tools</p>
          <p className="text-[10px] text-text-dim leading-relaxed">
            Short links run in-app above. Use these sites for advanced JWT editing, pipelines, or URL encoding.
          </p>
          <div className="grid gap-2 sm:grid-cols-3">
            <a
              href="https://gchq.github.io/CyberChef/"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-start gap-2 rounded-lg border border-border bg-bg/60 px-3 py-2 text-[11px] text-text-muted hover:border-accent/50 hover:text-white transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5 text-accent shrink-0 mt-0.5" />
              <span>
                <span className="font-semibold text-white block">CyberChef</span>
                Pipelines for encode/decode, crypto, compression, and more.
              </span>
            </a>
            <a
              href="https://www.urlencoder.org/"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-start gap-2 rounded-lg border border-border bg-bg/60 px-3 py-2 text-[11px] text-text-muted hover:border-accent/50 hover:text-white transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5 text-accent shrink-0 mt-0.5" />
              <span>
                <span className="font-semibold text-white block">URL encode / obfuscate</span>
                Percent-encode links and query strings for safer sharing in plain text.
              </span>
            </a>
            <a
              href="https://jwt.io/"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-start gap-2 rounded-lg border border-border bg-bg/60 px-3 py-2 text-[11px] text-text-muted hover:border-accent/50 hover:text-white transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5 text-accent shrink-0 mt-0.5" />
              <span>
                <span className="font-semibold text-white block">jwt.io</span>
                Decode JWTs, inspect headers/payload, and test signatures (third‑party).
              </span>
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
