import { NextRequest, NextResponse } from "next/server";
import { buildCodeReviewPdfBuffer } from "@/lib/build-code-review-pdf";
import { enrichReviewResult } from "@/lib/code-finding-enrich";
import { guardArgusRequest } from "@/lib/api-guard";
import { readJsonBodyLimited, validateCodeReviewPdfPayload } from "@/lib/pdf-payload-guard";
import { argusAudit } from "@/lib/argus-audit";

export async function POST(req: NextRequest) {
  try {
    const denied = guardArgusRequest(req);
    if (denied) return denied;
    const rawBody = await readJsonBodyLimited(req);
    if (rawBody instanceof NextResponse) return rawBody;
    const validated = validateCodeReviewPdfPayload(rawBody);
    if (validated instanceof NextResponse) return validated;
    const result = enrichReviewResult(validated);
    argusAudit("pdf_code_review", { findings: result.findings.length });
    const preparedBy =
      typeof rawBody === "object" &&
      rawBody !== null &&
      typeof (rawBody as { reportPreparedBy?: unknown }).reportPreparedBy === "string"
        ? (rawBody as { reportPreparedBy: string }).reportPreparedBy
        : undefined;
    const buf = await buildCodeReviewPdfBuffer(result, { reportPreparedBy: preparedBy });
    return new NextResponse(Buffer.from(buf), {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": 'attachment; filename="argus-code-review.pdf"',
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "PDF build failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
