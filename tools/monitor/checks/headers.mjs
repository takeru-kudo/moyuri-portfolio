// Security headers on Prod (full baseline) and Beta (HSTS only; Beta content sits behind Access).

import {
  BETA_URL,
  CSP_DIRECTIVES,
  CSP_HASH_DIRECTIVES,
  CSP_HEADER,
  HSTS_MIN_MAX_AGE,
  PROD_HEADERS,
  PROD_URL,
} from "../config.mjs";
import { describeError, describeValue, fail, pass, request } from "../lib.mjs";

const HASH_SOURCE_RE = /^'sha(256|384|512)-[A-Za-z0-9+/]+={0,2}'$/;

/** Parses the max-age of a Strict-Transport-Security value. Returns null when missing or invalid. */
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

/** Returns problems with the HSTS header, empty when it meets the minimum. */
export function hstsProblems(headers) {
  const value = headers.get("strict-transport-security");
  const maxAge = parseHstsMaxAge(value);
  if (maxAge === null) return [`HSTS missing or invalid: ${describeValue(value)}`];
  if (maxAge < HSTS_MIN_MAX_AGE) return [`HSTS max-age=${maxAge} below ${HSTS_MIN_MAX_AGE}`];
  return [];
}

/** Compares a CSP value with CSP_DIRECTIVES. Returns mismatch descriptions. */
export function cspProblems(value) {
  if (value === null) return [`${CSP_HEADER} missing`];
  const served = new Map();
  for (const part of value.split(";")) {
    const [name, ...sources] = part.trim().split(/\s+/).filter((t) => t !== "");
    if (name === undefined) continue;
    const key = name.toLowerCase();
    if (served.has(key)) return [`CSP directive ${key} repeated`];
    served.set(key, sources);
  }
  const problems = [];
  const expected = new Map(CSP_DIRECTIVES);
  for (const name of served.keys()) {
    if (!expected.has(name)) problems.push(`CSP unexpected directive ${name}`);
  }
  for (const [name, sources] of expected) {
    const actual = served.get(name);
    if (actual === undefined) {
      problems.push(`CSP missing directive ${name}`);
      continue;
    }
    const hashAllowed = CSP_HASH_DIRECTIVES.includes(name);
    const fixed = actual.filter((s) => !(hashAllowed && HASH_SOURCE_RE.test(s)));
    if (fixed.join(" ") !== sources.join(" ")) problems.push(`CSP directive ${name} differs`);
  }
  return problems;
}

/** Returns all baseline problems for the production response headers. */
export function prodProblems(headers) {
  const problems = [];
  for (const [name, value] of PROD_HEADERS) {
    const actual = headers.get(name);
    if (actual === null) problems.push(`${name} missing`);
    else if (actual.trim() !== value) problems.push(`${name} is ${describeValue(actual)}`);
  }
  problems.push(...cspProblems(headers.get(CSP_HEADER)));
  problems.push(...hstsProblems(headers));
  return problems;
}

async function head(ctx, url) {
  const target = new URL(url);
  target.searchParams.set("monitor", String(ctx.now()));
  return request(ctx, target, { method: "HEAD", headers: { "cache-control": "no-cache" } });
}

export async function run(ctx) {
  const results = [];

  try {
    const res = await head(ctx, PROD_URL);
    const problems = res.status === 200 ? [] : [`status ${res.status}`];
    problems.push(...prodProblems(res.headers));
    results.push(
      problems.length === 0
        ? pass("headers-prod")
        : fail("headers-prod", `${problems.length} problem(s): ${problems.join("; ")}`),
    );
  } catch (err) {
    results.push(fail("headers-prod", describeError(err)));
  }

  try {
    const res = await head(ctx, BETA_URL);
    const problems = hstsProblems(res.headers);
    results.push(problems.length === 0 ? pass("headers-beta-hsts") : fail("headers-beta-hsts", problems.join("; ")));
  } catch (err) {
    results.push(fail("headers-beta-hsts", describeError(err)));
  }

  return results;
}
