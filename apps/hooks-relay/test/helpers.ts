// Test helpers: webhook signing, test RSA keys and request builders.

import type { Env } from "../src/index.ts";

export const SECRET = "test-webhook-secret";

export function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sign(body: string | Uint8Array, secret: string = SECRET): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const data = typeof body === "string" ? new TextEncoder().encode(body) : body;
  return toHex(await crypto.subtle.sign("HMAC", key, data));
}

function toPem(der: ArrayBuffer, label: string): string {
  let binary = "";
  for (const byte of new Uint8Array(der)) {
    binary += String.fromCharCode(byte);
  }
  const lines = btoa(binary).match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

export interface TestKey {
  pem: string;
  publicKey: CryptoKey;
}

export async function generateTestKey(): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const der = (await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer;
  return { pem: toPem(der, "PRIVATE KEY"), publicKey: pair.publicKey };
}

export function makeEnv(pem: string, overrides: Partial<Env> = {}): Env {
  return {
    MICROCMS_WEBHOOK_SECRET: SECRET,
    GITHUB_APP_PRIVATE_KEY: pem,
    GITHUB_APP_ID: "12345",
    GITHUB_INSTALLATION_ID: "67890",
    GITHUB_OWNER: "takeru-kudo",
    GITHUB_REPO: "moyuri-portfolio",
    CF_VERSION_METADATA: { id: "11111111-2222-3333-4444-555555555555", tag: "", timestamp: "" },
    ...overrides,
  };
}

export async function signedRequest(body: string, signature?: string | null): Promise<Request> {
  const headers = new Headers({ "Content-Type": "application/json" });
  const value = signature === undefined ? await sign(body) : signature;
  if (value !== null) {
    headers.set("x-microcms-signature", value);
  }
  return new Request("https://hooks.moyuri-kudo.com/microcms", { method: "POST", headers, body });
}

export function webhookBody(api: string, id: string, oldStatus: string[] | null, newStatus: string[] | null): string {
  return JSON.stringify({
    service: "example",
    api,
    id,
    type: newStatus === null ? "delete" : oldStatus === null ? "new" : "edit",
    contents: {
      old: oldStatus === null ? null : { id, status: oldStatus, draftKey: null },
      new: newStatus === null ? null : { id, status: newStatus, draftKey: null },
    },
  });
}

export function decodeJwtPart(part: string): Record<string, unknown> {
  const b64 = part.replaceAll("-", "+").replaceAll("_", "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return JSON.parse(atob(padded)) as Record<string, unknown>;
}

export function base64UrlToBytes(part: string): Uint8Array {
  const b64 = part.replaceAll("-", "+").replaceAll("_", "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}
