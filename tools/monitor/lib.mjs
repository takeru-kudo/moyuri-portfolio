// Shared helpers for the daily monitor checks. Node.js built-ins only.

export const PASS = "PASS";
export const FAIL = "FAIL";
export const SKIP = "SKIP";

export const DAY_MS = 24 * 60 * 60 * 1000;
export const REQUEST_TIMEOUT_MS = 15_000;
export const USER_AGENT = "moyuri-portfolio-monitor";

const MAX_LOGGED_CHARS = 80;

export function pass(name, detail = "") {
  return { name, status: PASS, detail };
}

export function fail(name, detail) {
  return { name, status: FAIL, detail };
}

export function skip(name, detail) {
  return { name, status: SKIP, detail };
}

/** Result for a check whose credential is missing: SKIP, or FAIL when credentials are required. */
export function missingCredential(ctx, name, what) {
  const detail = `${what} not set`;
  return ctx.requireCredentials ? fail(name, detail) : skip(name, detail);
}

/** Formats an untrusted value for a single log line. */
export function describeValue(value) {
  if (value === null || value === undefined) return "(missing)";
  const text = String(value).replace(/[\r\n\t]/g, " ");
  const cut = text.length > MAX_LOGGED_CHARS ? `${text.slice(0, MAX_LOGGED_CHARS)}...` : text;
  return JSON.stringify(cut);
}

/** Formats an error as its name plus the underlying cause code, if any. Never includes the message. */
export function describeError(err) {
  const name = err?.name ?? "Error";
  const code = err?.code ?? err?.cause?.code ?? err?.cause?.name;
  return code ? `${name} (${code})` : name;
}

/** Whole days from `now` until `date` (negative when past). */
export function daysUntil(date, now) {
  return Math.floor((date.getTime() - now) / DAY_MS);
}

/** Parses a YYYY-MM-DD date as midnight UTC. Returns null when invalid. */
export function parseIsoDay(text) {
  if (typeof text !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(text)) return null;
  const date = new Date(`${text}T00:00:00Z`);
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== text) return null;
  return date;
}

/** Returns the YYYY-MM-DD UTC day `offsetDays` from `now`. */
export function utcDay(now, offsetDays = 0) {
  return new Date(now + offsetDays * DAY_MS).toISOString().slice(0, 10);
}

/** fetch with a timeout, no caching and a fixed User-Agent. */
export function request(ctx, url, init = {}) {
  return ctx.fetch(url, {
    redirect: "manual",
    cache: "no-store",
    ...init,
    headers: { "user-agent": USER_AGENT, ...(init.headers ?? {}) },
    signal: AbortSignal.timeout(ctx.timeoutMs ?? REQUEST_TIMEOUT_MS),
  });
}

/** GETs a URL and parses the JSON body. Throws HttpError on a non-2xx status. */
export async function getJson(ctx, url, init = {}) {
  const res = await request(ctx, url, init);
  if (res.status < 200 || res.status > 299) {
    await res.body?.cancel?.();
    throw new HttpError(res.status);
  }
  return { body: await res.json(), headers: res.headers };
}

export class HttpError extends Error {
  constructor(status) {
    super(`HTTP ${status}`);
    this.name = "HttpError";
    this.code = `status ${status}`;
    this.status = status;
  }
}

/** Retries `fn` up to `attempts` times, sleeping `delayMs` between failures. */
export async function withRetry(ctx, attempts, delayMs, fn) {
  let lastError;
  for (let i = 0; i < attempts; i += 1) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (i < attempts - 1) await ctx.sleep(delayMs);
    }
  }
  throw lastError;
}

/** Removes comments and trailing commas from JSONC text, leaving string contents untouched. */
export function stripJsonc(text) {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i += 1;
    } else if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 2;
    } else {
      out += ch;
      i += 1;
    }
  }
  return removeTrailingCommas(out);
}

function removeTrailingCommas(text) {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (ch === ",") {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j])) j += 1;
      if (text[j] === "}" || text[j] === "]") {
        i += 1;
        continue;
      }
    }
    out += ch;
    i += 1;
  }
  return out;
}
