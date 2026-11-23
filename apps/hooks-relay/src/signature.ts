// Verifies the x-microcms-signature header (hex HMAC-SHA256 of the raw body).

const HEX_SHA256 = /^[0-9a-f]{64}$/i;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Returns true when signature is the hex HMAC-SHA256 of body under secret. Comparison is done by crypto.subtle.verify. */
export async function verifySignature(secret: string, body: Uint8Array, signature: string | null): Promise<boolean> {
  if (secret.length === 0 || signature === null || !HEX_SHA256.test(signature)) {
    return false;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify("HMAC", key, hexToBytes(signature), body);
}
