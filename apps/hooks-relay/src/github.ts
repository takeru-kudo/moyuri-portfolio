// GitHub App authentication (RS256 JWT via WebCrypto) and the deploy.yml workflow_dispatch call.

import type { Target } from "./routing.ts";

export const GITHUB_API = "https://api.github.com";
export const USER_AGENT = "moyuri-portfolio-hooks-relay";
export const WORKFLOW_FILE = "deploy.yml";
export const DISPATCH_REF = "main";
const API_VERSION = "2022-11-28";
const TIMEOUT_MS = 10_000;
const IAT_SKEW_SECONDS = 60;
const EXP_SECONDS = 9 * 60;

export interface GitHubConfig {
  appId: string;
  installationId: string;
  owner: string;
  repo: string;
  privateKeyPem: string;
}

export class GitHubError extends Error {
  readonly step: string;
  readonly status: number | undefined;

  constructor(step: string, status?: number) {
    super(`GitHub ${step} failed${status === undefined ? "" : ` with status ${status}`}`);
    this.step = step;
    this.status = status;
  }
}

const NUMERIC_ID = /^[1-9][0-9]{0,19}$/;
const NAME = /^[A-Za-z0-9_.-]{1,100}$/;

/** Returns true when the non-secret GitHub settings are well-formed. */
export function isValidConfig(config: Omit<GitHubConfig, "privateKeyPem">): boolean {
  return (
    NUMERIC_ID.test(config.appId) &&
    NUMERIC_ID.test(config.installationId) &&
    NAME.test(config.owner) &&
    NAME.test(config.repo)
  );
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlEncodeJson(value: unknown): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

let cachedKey: { pem: string; key: CryptoKey } | undefined;

/** Imports a PKCS#8 PEM RSA private key for RS256 signing. Caches the last imported key. */
export async function importPrivateKey(pem: string): Promise<CryptoKey> {
  if (cachedKey?.pem === pem) {
    return cachedKey.key;
  }
  const match = /-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----/.exec(pem);
  if (match === null) {
    throw new GitHubError("key import");
  }
  let der: Uint8Array;
  try {
    der = Uint8Array.from(atob(match[1].replace(/\s+/g, "")), (c) => c.charCodeAt(0));
  } catch {
    throw new GitHubError("key import");
  }
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, [
      "sign",
    ]);
  } catch {
    throw new GitHubError("key import");
  }
  cachedKey = { pem, key };
  return key;
}

/** Creates the App JWT: iat 60 s in the past, exp 9 min ahead, iss = App ID. */
export async function createAppJwt(appId: string, privateKeyPem: string, nowSeconds: number): Promise<string> {
  const key = await importPrivateKey(privateKeyPem);
  const header = base64UrlEncodeJson({ alg: "RS256", typ: "JWT" });
  const payload = base64UrlEncodeJson({
    iat: nowSeconds - IAT_SKEW_SECONDS,
    exp: nowSeconds + EXP_SECONDS,
    iss: appId,
  });
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
}

function headers(token: string): HeadersInit {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "User-Agent": USER_AGENT,
    "X-GitHub-Api-Version": API_VERSION,
  };
}

async function post(step: string, url: string, token: string, body: unknown): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: headers(token),
      body: JSON.stringify(body),
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    throw new GitHubError(step);
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new GitHubError(step, response.status);
  }
  return response;
}

/** Requests an installation token limited to actions: write on the one repository. */
export async function createInstallationToken(config: GitHubConfig, jwt: string): Promise<string> {
  const response = await post(
    "token",
    `${GITHUB_API}/app/installations/${config.installationId}/access_tokens`,
    jwt,
    { repositories: [config.repo], permissions: { actions: "write" } },
  );
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw new GitHubError("token", response.status);
  }
  const token = typeof data === "object" && data !== null ? (data as { token?: unknown }).token : undefined;
  if (typeof token !== "string" || token.length === 0) {
    throw new GitHubError("token", response.status);
  }
  return token;
}

/** Dispatches deploy.yml on main with the given target and reason. Returns the response status. */
export async function dispatchDeploy(
  config: GitHubConfig,
  target: Target,
  reason: string,
  nowSeconds: number,
): Promise<number> {
  const jwt = await createAppJwt(config.appId, config.privateKeyPem, nowSeconds);
  const token = await createInstallationToken(config, jwt);
  const response = await post(
    "dispatch",
    `${GITHUB_API}/repos/${config.owner}/${config.repo}/actions/workflows/${WORKFLOW_FILE}/dispatches`,
    token,
    { ref: DISPATCH_REF, inputs: { target, reason } },
  );
  await response.body?.cancel();
  return response.status;
}
