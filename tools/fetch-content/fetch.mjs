// Fetches all microCMS content APIs and writes one JSON file per endpoint.
// Node.js built-ins only.
//
// Usage: node tools/fetch-content/fetch.mjs --mode published|draft --out <dir>
// Env:   MICROCMS_SERVICE_ID, and MICROCMS_API_KEY_PUBLISHED (published) or
//        MICROCMS_API_KEY_DRAFT (draft)

import { mkdir, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";

export const ENDPOINTS = Object.freeze([
  { name: "categories", kind: "list" },
  { name: "projects", kind: "list" },
  { name: "profile", kind: "object" },
  { name: "site", kind: "object" },
]);

export const KEY_ENV = Object.freeze({
  published: "MICROCMS_API_KEY_PUBLISHED",
  draft: "MICROCMS_API_KEY_DRAFT",
});

export const PAGE_LIMIT = 100;
export const MAX_ITEMS = 10_000;
export const MAX_ATTEMPTS = 3;
export const REQUEST_TIMEOUT_MS = 15_000;
export const MAX_RETRY_DELAY_MS = 30_000;

const SERVICE_ID_RE = /^[a-z0-9-]{3,32}$/;
const KEY_RE = /^[\x21-\x7e]{1,256}$/;

/** Error whose message is fixed text that is safe to print. */
export class FetchContentError extends Error {
  constructor(message) {
    super(message);
    this.name = "FetchContentError";
  }
}

/** Parses CLI arguments into { mode, out }, or throws FetchContentError. */
export function parseCli(argv) {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: { mode: { type: "string" }, out: { type: "string" } },
      strict: true,
      allowPositionals: false,
    }));
  } catch {
    throw new FetchContentError("usage: fetch.mjs --mode published|draft --out <dir>");
  }
  if (values.mode !== "published" && values.mode !== "draft") {
    throw new FetchContentError("--mode must be published or draft");
  }
  if (typeof values.out !== "string" || values.out === "") {
    throw new FetchContentError("--out is required");
  }
  return { mode: values.mode, out: values.out };
}

/** Reads the service ID and the API key for the mode from env, or throws. */
export function readConfig(mode, env) {
  const keyEnv = KEY_ENV[mode];
  if (!keyEnv) throw new FetchContentError("--mode must be published or draft");
  const serviceId = env.MICROCMS_SERVICE_ID ?? "";
  if (!SERVICE_ID_RE.test(serviceId)) {
    throw new FetchContentError("MICROCMS_SERVICE_ID is missing or invalid");
  }
  const apiKey = env[keyEnv] ?? "";
  if (!KEY_RE.test(apiKey)) {
    throw new FetchContentError(`${keyEnv} is missing or invalid`);
  }
  return { serviceId, apiKey };
}

function retryDelayMs(res, attempt) {
  const header = res.headers.get("retry-after");
  if (header !== null && /^[0-9]{1,5}$/.test(header.trim())) {
    return Math.min(Number(header.trim()) * 1000, MAX_RETRY_DELAY_MS);
  }
  return Math.min(1000 * 2 ** (attempt - 1), MAX_RETRY_DELAY_MS);
}

function describeRequestError(err) {
  const name = typeof err?.name === "string" ? err.name : "Error";
  const code = err?.cause?.code ?? err?.cause?.name;
  const safe = (v) => String(v).replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 40);
  return code ? `${safe(name)} (${safe(code)})` : safe(name);
}

/**
 * GETs one URL with timeout and bounded retry on 429/5xx.
 * Returns the parsed JSON body, or throws FetchContentError naming only the endpoint.
 */
export async function getJson(url, endpoint, deps) {
  for (let attempt = 1; ; attempt++) {
    let res;
    try {
      res = await deps.fetch(url, {
        method: "GET",
        headers: { "X-MICROCMS-API-KEY": deps.apiKey, Accept: "application/json" },
        redirect: "error",
        signal: AbortSignal.timeout(deps.timeoutMs ?? REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      throw new FetchContentError(`${endpoint}: request failed: ${describeRequestError(err)}`);
    }
    if (res.ok) {
      try {
        return await res.json();
      } catch (err) {
        if (err?.name === "TimeoutError" || err?.name === "AbortError") {
          throw new FetchContentError(`${endpoint}: request failed: ${describeRequestError(err)}`);
        }
        throw new FetchContentError(`${endpoint}: response is not valid JSON`);
      }
    }
    const retryable = res.status === 429 || (res.status >= 500 && res.status <= 599);
    await res.body?.cancel().catch(() => {});
    if (!retryable || attempt >= MAX_ATTEMPTS) {
      throw new FetchContentError(`${endpoint}: HTTP ${res.status}`);
    }
    deps.log(`${endpoint}: HTTP ${res.status}, retrying (${attempt}/${MAX_ATTEMPTS - 1})`);
    await deps.sleep(retryDelayMs(res, attempt));
  }
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isContentLike(value) {
  return (
    isPlainObject(value) &&
    typeof value.id === "string" &&
    typeof value.createdAt === "string" &&
    typeof value.updatedAt === "string"
  );
}

/**
 * Returns the number of content objects (the value itself and any embedded
 * relation objects) that have no publishedAt.
 */
export function countUnpublished(value, isRoot = true) {
  let count = 0;
  if (isPlainObject(value)) {
    const content = isRoot || isContentLike(value);
    if (content && (typeof value.publishedAt !== "string" || value.publishedAt === "")) count++;
    for (const child of Object.values(value)) count += countUnpublished(child, false);
  } else if (Array.isArray(value)) {
    for (const child of value) count += countUnpublished(child, false);
  }
  return count;
}

function buildUrl(serviceId, endpoint, params) {
  const url = new URL(`https://${serviceId}.microcms.io/api/v1/${endpoint}`);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
  return url.toString();
}

/** Fetches every item of a list API, following offset pagination. */
export async function fetchList(endpoint, deps) {
  const items = [];
  const ids = new Set();
  let total = null;
  while (total === null || items.length < total) {
    const url = buildUrl(deps.serviceId, endpoint, { limit: PAGE_LIMIT, offset: items.length });
    const body = await getJson(url, endpoint, deps);
    if (!isPlainObject(body) || !Array.isArray(body.contents)) {
      throw new FetchContentError(`${endpoint}: response has no contents array`);
    }
    const count = body.totalCount;
    if (!Number.isSafeInteger(count) || count < 0 || count > MAX_ITEMS) {
      throw new FetchContentError(`${endpoint}: totalCount is invalid`);
    }
    if (total !== null && count !== total) {
      throw new FetchContentError(`${endpoint}: totalCount changed during pagination`);
    }
    total = count;
    if (items.length < total && body.contents.length === 0) {
      throw new FetchContentError(`${endpoint}: page is empty before totalCount was reached`);
    }
    for (const item of body.contents) {
      if (!isPlainObject(item) || typeof item.id !== "string" || item.id === "") {
        throw new FetchContentError(`${endpoint}: item without a string id`);
      }
      if (ids.has(item.id)) {
        throw new FetchContentError(`${endpoint}: duplicate item id`);
      }
      ids.add(item.id);
      items.push(item);
    }
    if (items.length > total) {
      throw new FetchContentError(`${endpoint}: more items than totalCount`);
    }
  }
  return { contents: items, totalCount: total };
}

/** Fetches an object API. */
export async function fetchObject(endpoint, deps) {
  const body = await getJson(buildUrl(deps.serviceId, endpoint, {}), endpoint, deps);
  if (!isPlainObject(body)) {
    throw new FetchContentError(`${endpoint}: response is not an object`);
  }
  return body;
}

/** Fails if published-mode data contains content that is not published. */
export function assertPublished(endpoint, kind, data) {
  const roots = kind === "list" ? data.contents : [data];
  let unpublished = 0;
  for (const root of roots) unpublished += countUnpublished(root);
  if (unpublished > 0) {
    throw new FetchContentError(
      `${endpoint}: ${unpublished} unpublished content object(s) in published mode`,
    );
  }
}

/** Fails unless out is absent or an empty directory. */
export async function assertEmptyOut(out) {
  let entries;
  try {
    entries = await readdir(out);
  } catch (err) {
    if (err?.code === "ENOENT") return;
    throw new FetchContentError("--out must be an empty directory or not exist");
  }
  if (entries.length > 0) throw new FetchContentError("--out must be an empty directory or not exist");
}

/** Fetches all endpoints, then writes <out>/<endpoint>.json for each. */
export async function run({ mode, out, env, fetchImpl, sleep, log, timeoutMs }) {
  const { serviceId, apiKey } = readConfig(mode, env);
  await assertEmptyOut(out);
  const deps = { fetch: fetchImpl, sleep, log, serviceId, apiKey, timeoutMs };
  const results = [];
  for (const { name, kind } of ENDPOINTS) {
    const data = kind === "list" ? await fetchList(name, deps) : await fetchObject(name, deps);
    if (mode === "published") assertPublished(name, kind, data);
    results.push({ name, kind, data });
  }
  await mkdir(out, { recursive: true });
  for (const { name, kind, data } of results) {
    await writeFile(path.join(out, `${name}.json`), `${JSON.stringify(data, null, 2)}\n`, {
      mode: 0o600,
    });
    log(kind === "list" ? `${name}: ${data.contents.length} items` : `${name}: 1 object`);
  }
}

async function main() {
  const log = (line) => process.stdout.write(`fetch-content: ${line}\n`);
  try {
    const { mode, out } = parseCli(process.argv.slice(2));
    await run({ mode, out, env: process.env, fetchImpl: globalThis.fetch, sleep: delay, log });
    return 0;
  } catch (err) {
    const message =
      err instanceof FetchContentError ? err.message : `unexpected error (${describeRequestError(err)})`;
    process.stderr.write(`fetch-content: error: ${message}\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}
