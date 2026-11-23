// Production smoke check run right after `wrangler versions deploy`.
// Node.js built-ins only.
//
// Exit codes:
//   0 = pass
//   3 = only the HSTS baseline failed
//   any other non-zero = failure (including unexpected errors)

import { setTimeout as delay } from "node:timers/promises";

export const EXIT_OK = 0;
export const EXIT_FAIL = 1;
export const EXIT_HSTS_ONLY = 3;

export const DEFAULT_BASE_URL = "https://moyuri-kudo.com";
export const EXPECTED_TEXT = "Moyuri Kudo";
export const HSTS_MIN_MAX_AGE = 300;
export const CSP_HEADER = "content-security-policy-report-only";
export const CSP_REQUIRED_DIRECTIVE = "default-src 'none'";
export const POLL_INTERVAL_MS = 10_000;
export const POLL_TIMEOUT_MS = 5 * 60_000;
export const REQUEST_TIMEOUT_MS = 10_000;

const SHA_RE = /^[0-9a-f]{40}$/;
const RUN_ID_RE = /^[0-9]{1,20}$/;
const MAX_LOGGED_CHARS = 80;

/** Formats an untrusted value for a single log line. */
export function describeValue(value) {
  if (value === null || value === undefined) return "(missing)";
  const text = String(value);
  const cut = text.length > MAX_LOGGED_CHARS ? `${text.slice(0, MAX_LOGGED_CHARS)}...` : text;
  return JSON.stringify(cut);
}

/** Formats a request error as its name plus the underlying cause code, if any. */
export function describeError(err) {
  const name = err?.name ?? "Error";
  const code = err?.cause?.code ?? err?.cause?.name;
  return describeValue(code ? `${name} (${code})` : name);
}

/** Returns "<sha>-<run_id>" from the runner environment, or throws. */
export function expectedVersion(env) {
  const sha = env.GITHUB_SHA ?? "";
  const runId = env.GITHUB_RUN_ID ?? "";
  if (!SHA_RE.test(sha)) throw new Error("GITHUB_SHA is missing or not a 40-character hex SHA");
  if (!RUN_ID_RE.test(runId)) throw new Error("GITHUB_RUN_ID is missing or not numeric");
  return `${sha}-${runId}`;
}

/** Returns the base URL (origin only), or throws. */
export function resolveBaseUrl(env) {
  const raw = env.SMOKE_BASE_URL || DEFAULT_BASE_URL;
  const url = new URL(raw);
  if (url.protocol !== "https:" && url.hostname !== "127.0.0.1" && url.hostname !== "localhost") {
    throw new Error("SMOKE_BASE_URL must use https");
  }
  return url.origin;
}

/**
 * Parses the max-age of a Strict-Transport-Security value (RFC 6797 §6.1).
 * Returns the integer, or null when the header is missing or invalid.
 */
export function parseHstsMaxAge(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  let maxAge = null;
  const seen = new Set();
  for (const part of value.split(";")) {
    const directive = part.trim();
    if (directive === "") continue;
    const eq = directive.indexOf("=");
    const name = (eq === -1 ? directive : directive.slice(0, eq)).trim().toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) return null;
    if (seen.has(name)) return null;
    seen.add(name);
    if (name !== "max-age") continue;
    if (eq === -1) return null;
    let raw = directive.slice(eq + 1).trim();
    if (raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"')) raw = raw.slice(1, -1);
    if (!/^[0-9]{1,15}$/.test(raw)) return null;
    maxAge = Number.parseInt(raw, 10);
  }
  return maxAge;
}

/**
 * Checks the header baseline on a Headers-like object.
 * Returns a list of failures: { kind: "hsts" | "header", message }.
 */
export function checkHeaders(headers) {
  const failures = [];
  const nosniff = headers.get("x-content-type-options");
  if (nosniff === null || nosniff.trim().toLowerCase() !== "nosniff") {
    failures.push({
      kind: "header",
      message: `X-Content-Type-Options is ${describeValue(nosniff)}, expected "nosniff"`,
    });
  }
  const csp = headers.get(CSP_HEADER);
  const directives = (csp ?? "").split(";").map((d) => d.trim().replace(/\s+/g, " ").toLowerCase());
  if (!directives.includes(CSP_REQUIRED_DIRECTIVE)) {
    failures.push({
      kind: "header",
      message: `${CSP_HEADER} is ${describeValue(csp)}, expected a policy with "${CSP_REQUIRED_DIRECTIVE}"`,
    });
  }
  const hsts = headers.get("strict-transport-security");
  const maxAge = parseHstsMaxAge(hsts);
  if (maxAge === null) {
    failures.push({
      kind: "hsts",
      message: `Strict-Transport-Security is missing or invalid: ${describeValue(hsts)}`,
    });
  } else if (maxAge < HSTS_MIN_MAX_AGE) {
    failures.push({
      kind: "hsts",
      message: `Strict-Transport-Security max-age=${maxAge} is below ${HSTS_MIN_MAX_AGE}`,
    });
  }
  return failures;
}

/** Maps a failure list to an exit code. */
export function classify(failures) {
  if (failures.length === 0) return EXIT_OK;
  if (failures.every((f) => f.kind === "hsts")) return EXIT_HSTS_ONLY;
  return EXIT_FAIL;
}

async function request(fetchImpl, url) {
  return fetchImpl(url, {
    method: "GET",
    cache: "no-store",
    redirect: "manual",
    headers: { "cache-control": "no-cache", pragma: "no-cache" },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
}

/**
 * Polls /version.txt until its trimmed body equals `expected`.
 * Returns { ok: true, attempts } or { ok: false, attempts, last }.
 */
export async function waitForVersion({
  baseUrl,
  expected,
  fetchImpl = fetch,
  now = Date.now,
  sleep = delay,
  log = console.log,
  intervalMs = POLL_INTERVAL_MS,
  timeoutMs = POLL_TIMEOUT_MS,
}) {
  const deadline = now() + timeoutMs;
  let attempts = 0;
  let last = "(no response)";
  for (;;) {
    attempts += 1;
    const url = new URL("/version.txt", baseUrl);
    url.searchParams.set("smoke", `${now()}-${attempts}`);
    try {
      const res = await request(fetchImpl, url);
      const body = await res.text();
      if (res.status === 200 && body.trim() === expected) {
        log(`version.txt matched after ${attempts} attempt(s)`);
        return { ok: true, attempts };
      }
      last = `status ${res.status}, body ${describeValue(body.trim())}`;
    } catch (err) {
      last = `request error: ${describeError(err)}`;
    }
    log(`version.txt attempt ${attempts}: ${last}`);
    if (now() + intervalMs > deadline) return { ok: false, attempts, last };
    await sleep(intervalMs);
  }
}

/** Fetches / and returns its failures (status, text, header baseline). */
export async function checkHome({ baseUrl, fetchImpl = fetch }) {
  const url = new URL("/", baseUrl);
  url.searchParams.set("smoke", String(Date.now()));
  let res;
  try {
    res = await request(fetchImpl, url);
  } catch (err) {
    return [{ kind: "status", message: `GET / failed: ${describeError(err)}` }];
  }
  const failures = [];
  const body = await res.text();
  if (res.status !== 200) {
    failures.push({ kind: "status", message: `GET / returned status ${res.status}, expected 200` });
  }
  if (!body.includes(EXPECTED_TEXT)) {
    failures.push({ kind: "text", message: `GET / body does not contain ${JSON.stringify(EXPECTED_TEXT)}` });
  }
  failures.push(...checkHeaders(res.headers));
  return failures;
}

/** Runs the full smoke check and returns an exit code. */
export async function run({ env = process.env, fetchImpl = fetch, now, sleep, log = console.log } = {}) {
  let baseUrl;
  let expected;
  try {
    baseUrl = resolveBaseUrl(env);
    expected = expectedVersion(env);
  } catch (err) {
    log(`smoke: configuration error: ${err.message}`);
    return EXIT_FAIL;
  }
  log(`smoke: base ${baseUrl}, waiting for version ${expected}`);

  const version = await waitForVersion({ baseUrl, expected, fetchImpl, now, sleep, log });
  if (!version.ok) {
    log(`smoke: FAIL version.txt did not match within the time limit (last: ${version.last})`);
    return EXIT_FAIL;
  }

  const failures = await checkHome({ baseUrl, fetchImpl });
  for (const f of failures) log(`smoke: FAIL [${f.kind}] ${f.message}`);
  const code = classify(failures);
  if (code === EXIT_OK) log("smoke: PASS");
  if (code === EXIT_HSTS_ONLY) log("smoke: only the HSTS baseline failed");
  return code;
}

if (import.meta.main) {
  process.exitCode = await run();
}
