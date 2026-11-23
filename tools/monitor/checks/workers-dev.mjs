// workers.dev must be disabled for every Worker: the API setting is off and the URL does not serve content.

import { CLOUDFLARE_API, WORKERS } from "../config.mjs";
import { HttpError, describeError, fail, getJson, missingCredential, pass, request } from "../lib.mjs";

const NAME = "workers-dev";
const SUBDOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ACCOUNT_RE = /^[0-9a-f]{32}$/;

function cfGet(ctx, token, url) {
  return getJson(ctx, url, { headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
}

/** Returns true when the Worker's workers.dev route is enabled, false when disabled, null when the Worker is absent. */
async function scriptEnabled(ctx, token, account, worker) {
  try {
    const { body } = await cfGet(ctx, token, `${CLOUDFLARE_API}/accounts/${account}/workers/scripts/${worker}/subdomain`);
    const enabled = body?.result?.enabled;
    if (body?.success !== true || typeof enabled !== "boolean") throw new TypeError("unexpected Workers API response");
    return enabled;
  } catch (err) {
    if (err instanceof HttpError && err.status === 404) return null;
    throw err;
  }
}

/** Returns a description when the workers.dev URL serves content, otherwise null. Throws on timeouts. */
async function probe(ctx, worker, path, subdomain) {
  const url = new URL(path, `https://${worker}.${subdomain}.workers.dev`);
  try {
    const res = await request(ctx, url, { method: "GET" });
    await res.body?.cancel?.();
    return res.status < 400 ? `${worker} URL status ${res.status}` : null;
  } catch (err) {
    if (err?.name === "TimeoutError") throw err;
    return null;
  }
}

export async function run(ctx) {
  const token = ctx.env.CLOUDFLARE_API_TOKEN ?? "";
  const account = ctx.env.CLOUDFLARE_ACCOUNT_ID ?? "";
  if (token === "") return [missingCredential(ctx, NAME, "CLOUDFLARE_API_TOKEN")];
  if (account === "") return [missingCredential(ctx, NAME, "CLOUDFLARE_ACCOUNT_ID")];
  if (!ACCOUNT_RE.test(account)) return [fail(NAME, "CLOUDFLARE_ACCOUNT_ID is malformed")];

  try {
    const { body } = await cfGet(ctx, token, `${CLOUDFLARE_API}/accounts/${account}/workers/subdomain`);
    const subdomain = body?.result?.subdomain;
    if (typeof subdomain !== "string" || !SUBDOMAIN_RE.test(subdomain)) {
      return [fail(NAME, "account workers.dev subdomain missing or invalid")];
    }
    const problems = [];
    let present = 0;
    for (const [worker, path, optional] of WORKERS) {
      const enabled = await scriptEnabled(ctx, token, account, worker);
      if (enabled !== null) present += 1;
      else if (!optional) problems.push(`${worker} not found`);
      if (enabled === true) problems.push(`${worker} enabled`);
      const served = await probe(ctx, worker, path, subdomain);
      if (served !== null) problems.push(served);
    }
    const detail = `${present} of ${WORKERS.length} Worker(s) exist`;
    return [problems.length === 0 ? pass(NAME, `${detail}, all disabled`) : fail(NAME, `${detail}; ${problems.join("; ")}`)];
  } catch (err) {
    return [fail(NAME, describeError(err))];
  }
}
