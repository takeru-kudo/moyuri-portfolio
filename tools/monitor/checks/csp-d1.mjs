// CSP violation reports stored in D1 by the csp-report Worker, queried with the Cloudflare D1 REST API.

import {
  CLOUDFLARE_API,
  CSP_DATABASE_NAME,
  CSP_DATABASE_PLACEHOLDER,
  CSP_NEW_VIOLATIONS_SQL,
  CSP_OVERFLOW_SQL,
  CSP_WRANGLER_CONFIG,
} from "../config.mjs";
import { HttpError, describeError, fail, missingCredential, pass, request, skip, stripJsonc, utcDay } from "../lib.mjs";

const NEW_NAME = "csp-new-violations";
const OVERFLOW_NAME = "csp-overflow";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ACCOUNT_RE = /^[0-9a-f]{32}$/;

/**
 * Returns the D1 database ID from the wrangler config text:
 * { id } when found, { skip } when not configured yet, or throws on a malformed config.
 */
export function databaseId(configText) {
  const config = JSON.parse(stripJsonc(configText));
  const dbs = Array.isArray(config?.d1_databases) ? config.d1_databases : [];
  const db = dbs.find((d) => d?.database_name === CSP_DATABASE_NAME);
  const id = db?.database_id;
  if (id === undefined || id === "" || id === CSP_DATABASE_PLACEHOLDER) return { skip: "database_id not set" };
  if (typeof id !== "string" || !UUID_RE.test(id)) throw new TypeError("database_id is not a UUID");
  return { id };
}

async function d1Count(ctx, url, token, sql, params) {
  const res = await request(ctx, url, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ sql, params }),
  });
  if (res.status !== 200) {
    await res.body?.cancel?.();
    throw new HttpError(res.status);
  }
  const body = await res.json();
  const n = body?.result?.[0]?.results?.[0]?.n;
  if (body?.success !== true || !Number.isInteger(n) || n < 0) throw new TypeError("unexpected D1 response");
  return n;
}

export async function run(ctx) {
  let configText;
  try {
    configText = await ctx.readFile(CSP_WRANGLER_CONFIG);
  } catch (err) {
    if (err?.code !== "ENOENT") return [fail(NEW_NAME, describeError(err)), fail(OVERFLOW_NAME, describeError(err))];
    const detail = `${CSP_WRANGLER_CONFIG} not found`;
    return [skip(NEW_NAME, detail), skip(OVERFLOW_NAME, detail)];
  }

  let db;
  try {
    db = databaseId(configText);
  } catch (err) {
    return [fail(NEW_NAME, describeError(err)), fail(OVERFLOW_NAME, describeError(err))];
  }
  if (db.skip) return [skip(NEW_NAME, db.skip), skip(OVERFLOW_NAME, db.skip)];

  const token = ctx.env.CLOUDFLARE_API_TOKEN ?? "";
  const account = ctx.env.CLOUDFLARE_ACCOUNT_ID ?? "";
  if (token === "" || account === "") {
    const what = token === "" ? "CLOUDFLARE_API_TOKEN" : "CLOUDFLARE_ACCOUNT_ID";
    return [missingCredential(ctx, NEW_NAME, what), missingCredential(ctx, OVERFLOW_NAME, what)];
  }
  if (!ACCOUNT_RE.test(account)) {
    return [fail(NEW_NAME, "CLOUDFLARE_ACCOUNT_ID is malformed"), fail(OVERFLOW_NAME, "CLOUDFLARE_ACCOUNT_ID is malformed")];
  }

  const url = `${CLOUDFLARE_API}/accounts/${account}/d1/database/${db.id}/query`;
  const yesterday = utcDay(ctx.now(), -1);
  const since = Date.parse(`${yesterday}T00:00:00Z`);
  const results = [];

  try {
    const n = await d1Count(ctx, url, token, CSP_NEW_VIOLATIONS_SQL, [since]);
    results.push(n === 0 ? pass(NEW_NAME, `0 new since ${yesterday}`) : fail(NEW_NAME, `${n} new since ${yesterday}`));
  } catch (err) {
    results.push(fail(NEW_NAME, describeError(err)));
  }

  try {
    const n = await d1Count(ctx, url, token, CSP_OVERFLOW_SQL, [yesterday]);
    results.push(n === 0 ? pass(OVERFLOW_NAME, `0 since ${yesterday}`) : fail(OVERFLOW_NAME, `${n} overflow report(s) since ${yesterday}`));
  } catch (err) {
    results.push(fail(OVERFLOW_NAME, describeError(err)));
  }

  return results;
}
