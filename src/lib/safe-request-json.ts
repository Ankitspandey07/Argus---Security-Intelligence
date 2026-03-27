import { NextResponse } from "next/server";

type ReadJsonResult =
  | { ok: true; body: unknown }
  | { ok: false; response: NextResponse };

/**
 * Read and parse JSON from a request body once.
 * Returns 400 for malformed JSON (avoids unhandled exceptions + generic 500s).
 */
export async function readJsonBody(req: Request): Promise<ReadJsonResult> {
  let text: string;
  try {
    text = await req.text();
  } catch {
    return {
      ok: false,
      response: NextResponse.json({ error: "Could not read request body" }, { status: 400 }),
    };
  }
  const t = text.trim();
  if (!t) return { ok: true, body: {} };
  try {
    return { ok: true, body: JSON.parse(t) as unknown };
  } catch {
    return { ok: false, response: NextResponse.json({ error: "Invalid JSON body" }, { status: 400 }) };
  }
}
