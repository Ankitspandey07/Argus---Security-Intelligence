import { NextRequest, NextResponse } from "next/server";
import { guardArgusRequest } from "@/lib/api-guard";
import { readJsonBody } from "@/lib/safe-request-json";
import { decodeJwtParts } from "@/lib/jwt-decode";
import { toASCII, toUnicode } from "node:punycode";

/**
 * Encode/decode utilities. JWT decode does NOT verify signatures.
 */
function rot13(s: string): string {
  return s.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode((((ch.charCodeAt(0) - base + 13) % 26) + base));
  });
}

function utf8ToBinaryString(s: string): string {
  const buf = Buffer.from(s, "utf8");
  return [...buf].map((b) => b.toString(2).padStart(8, "0")).join(" ");
}

function binaryStringToUtf8(s: string): { ok: boolean; text?: string; error?: string } {
  const bits = s.replace(/[^01]/g, "");
  if (bits.length % 8 !== 0) {
    return { ok: false, error: "Binary must be a multiple of 8 bits (after removing spaces)." };
  }
  const bytes: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  const buf = Buffer.from(bytes);
  try {
    return { ok: true, text: buf.toString("utf8") };
  } catch {
    return { ok: false, error: "Invalid UTF-8 from binary." };
  }
}

export async function POST(req: NextRequest) {
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const parsed = await readJsonBody(req);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body as Record<string, unknown>;
    const direction: "encode" | "decode" = body.direction === "encode" ? "encode" : "decode";

    const {
      jwt,
      base64,
      hex,
      urlText,
      base64url,
      htmlEntities,
      rot13: rot13in,
      unicodeCodepoints,
      binary,
      punycodeHost,
    } = body;

    if (jwt && typeof jwt === "string") {
      const dec = decodeJwtParts(jwt.trim());
      if (!dec) return NextResponse.json({ error: "Invalid JWT format" }, { status: 400 });
      return NextResponse.json({
        type: "jwt",
        direction: "decode",
        warning: "Payload decoded without signature verification. Treat as untrusted data.",
        header: dec.header,
        payload: dec.payload,
        signatureB64Url: dec.signature,
      });
    }

    if (base64 && typeof base64 === "string") {
      const s = base64.trim();
      if (direction === "encode") {
        const b64 = Buffer.from(s, "utf8").toString("base64");
        return NextResponse.json({
          type: "base64",
          direction: "encode",
          base64: b64,
          note: "UTF-8 text → standard Base64.",
        });
      }
      try {
        const buf = Buffer.from(s, "base64");
        const utf8 = buf.toString("utf8");
        const printable = /^[\x20-\x7E\n\r\t]+$/.test(utf8);
        return NextResponse.json({
          type: "base64",
          direction: "decode",
          warning: "Base64 is reversible encoding, not encryption.",
          utf8: printable ? utf8 : undefined,
          hex: buf.toString("hex"),
          bytes: buf.length,
        });
      } catch {
        return NextResponse.json({ error: "Invalid base64" }, { status: 400 });
      }
    }

    if (hex && typeof hex === "string") {
      if (direction === "encode") {
        const clean = hex.trim();
        const buf = Buffer.from(clean, "utf8");
        return NextResponse.json({
          type: "hex",
          direction: "encode",
          hex: buf.toString("hex"),
          bytes: buf.length,
        });
      }
      const clean = hex.replace(/\s/g, "");
      if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length % 2 !== 0) {
        return NextResponse.json({ error: "Invalid hex string" }, { status: 400 });
      }
      const buf = Buffer.from(clean, "hex");
      const utf8 = buf.toString("utf8");
      const printable = /^[\x20-\x7E\n\r\t]+$/.test(utf8);
      return NextResponse.json({
        type: "hex",
        direction: "decode",
        utf8: printable ? utf8 : undefined,
        base64: buf.toString("base64"),
        bytes: buf.length,
      });
    }

    if (urlText && typeof urlText === "string") {
      const s = urlText.trim();
      if (direction === "encode") {
        return NextResponse.json({
          type: "url",
          direction: "encode",
          encoded: encodeURIComponent(s),
          plusAsSpaceNote: "Uses encodeURIComponent (RFC 3986 component encoding).",
        });
      }
      return NextResponse.json({
        type: "url",
        direction: "decode",
        decoded: (() => {
          try {
            return decodeURIComponent(s.replace(/\+/g, " "));
          } catch {
            return null;
          }
        })(),
        encoded: encodeURIComponent(s),
        note: "decoded: decodeURIComponent (+ as space). encoded: encodeURIComponent.",
      });
    }

    if (base64url && typeof base64url === "string") {
      const s0 = base64url.trim();
      if (direction === "encode") {
        const std = Buffer.from(s0, "utf8").toString("base64");
        const b64url = std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        return NextResponse.json({
          type: "base64url",
          direction: "encode",
          base64url: b64url,
          standardBase64: std,
        });
      }
      let s = s0.replace(/-/g, "+").replace(/_/g, "/");
      const pad = s.length % 4;
      if (pad) s += "=".repeat(4 - pad);
      try {
        const buf = Buffer.from(s, "base64");
        const utf8 = buf.toString("utf8");
        return NextResponse.json({
          type: "base64url",
          direction: "decode",
          warning: "Base64url (JWT-style alphabet). Not encryption.",
          utf8,
          standardBase64: buf.toString("base64"),
          bytes: buf.length,
        });
      } catch {
        return NextResponse.json({ error: "Invalid base64url" }, { status: 400 });
      }
    }

    if (htmlEntities && typeof htmlEntities === "string") {
      const s = htmlEntities;
      const decoded = s
        .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
        .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/&quot;/gi, '"')
        .replace(/&#39;/g, "'")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&");
      const encoded = s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
      if (direction === "encode") {
        return NextResponse.json({
          type: "html_entities",
          direction: "encode",
          encodedAttributeSafe: encoded,
          note: "Basic entity encoding for < > & \".",
        });
      }
      return NextResponse.json({
        type: "html_entities",
        direction: "decode",
        decoded,
        encodedAttributeSafe: encoded,
        note: "Basic named + numeric entities.",
      });
    }

    if (rot13in && typeof rot13in === "string") {
      return NextResponse.json({
        type: "rot13",
        direction: "both",
        result: rot13(rot13in),
        note: "ROT13 is its own inverse.",
      });
    }

    if (unicodeCodepoints && typeof unicodeCodepoints === "string") {
      const s = unicodeCodepoints;
      if (direction === "encode") {
        const codePoints = [...s].map((ch) => {
          const cp = ch.codePointAt(0)!;
          return "U+" + cp.toString(16).toUpperCase().padStart(cp > 0xffff ? 6 : 4, "0");
        });
        return NextResponse.json({
          type: "unicode",
          direction: "encode",
          codePoints: codePoints.slice(0, 2000),
          truncated: codePoints.length > 2000,
        });
      }
      const codePoints = [...s].map((ch) => ({
        char: ch,
        hex: "U+" + ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0"),
        dec: ch.codePointAt(0),
      }));
      const escaped = [...s]
        .map((ch) => {
          const cp = ch.codePointAt(0)!;
          return cp > 255 ? `\\u{${cp.toString(16)}}` : `\\x${cp.toString(16).padStart(2, "0")}`;
        })
        .join("");
      return NextResponse.json({
        type: "unicode",
        direction: "decode",
        lengthChars: [...s].length,
        codePoints: codePoints.slice(0, 500),
        truncated: codePoints.length > 500,
        jsStyleEscapeSample: escaped.slice(0, 2000),
      });
    }

    if (binary && typeof binary === "string") {
      if (direction === "encode") {
        return NextResponse.json({
          type: "binary",
          direction: "encode",
          binary: utf8ToBinaryString(binary),
          note: "UTF-8 bytes as space-separated 8-bit groups.",
        });
      }
      const r = binaryStringToUtf8(binary);
      if (!r.ok) return NextResponse.json({ error: r.error || "Invalid binary" }, { status: 400 });
      return NextResponse.json({
        type: "binary",
        direction: "decode",
        utf8: r.text,
      });
    }

    if (punycodeHost && typeof punycodeHost === "string") {
      const s = punycodeHost.trim();
      try {
        if (direction === "encode") {
          const ascii = toASCII(s);
          return NextResponse.json({
            type: "punycode",
            direction: "encode",
            asciiHostname: ascii,
            note: "IDN → Punycode (ASCII) using node:punycode.",
          });
        }
        const unicode = toUnicode(s);
        return NextResponse.json({
          type: "punycode",
          direction: "decode",
          unicodeHostname: unicode,
          note: "Punycode (xn--…) → Unicode labels.",
        });
      } catch {
        return NextResponse.json({ error: "Invalid domain / punycode input" }, { status: 400 });
      }
    }

    return NextResponse.json(
      {
        error:
          "Provide one of: jwt, base64, hex, urlText, base64url, htmlEntities, rot13, unicodeCodepoints, binary, punycodeHost — optional direction: encode|decode",
      },
      { status: 400 },
    );
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Decode failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
