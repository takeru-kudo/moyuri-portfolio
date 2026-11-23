// Reads a request body up to a byte limit.

export const MAX_BODY_BYTES = 64 * 1024;

export type BodyResult = { ok: true; bytes: Uint8Array } | { ok: false; reason: "too_large" | "bad_length" };

/** Returns the body bytes, or too_large when Content-Length or the bytes read exceed maxBytes. */
export async function readBodyWithLimit(request: Request, maxBytes: number = MAX_BODY_BYTES): Promise<BodyResult> {
  const header = request.headers.get("content-length");
  if (header !== null) {
    if (!/^[0-9]+$/.test(header)) {
      return { ok: false, reason: "bad_length" };
    }
    if (Number(header) > maxBytes) {
      return { ok: false, reason: "too_large" };
    }
  }
  if (request.body === null) {
    return { ok: true, bytes: new Uint8Array(0) };
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return { ok: false, reason: "too_large" };
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, bytes };
}
