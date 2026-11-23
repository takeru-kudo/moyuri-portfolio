import assert from "node:assert/strict";
import { test } from "node:test";
import { CSP_DIRECTIVES, PROD_HEADERS } from "../config.mjs";
import { NOW, fakeFetch, makeCtx } from "../test-helpers.mjs";
import { cspProblems, parseHstsMaxAge, prodProblems, run } from "./headers.mjs";

const HASH = "'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='";

function goodCsp() {
  return CSP_DIRECTIVES.map(([name, sources]) => {
    const extra = name === "script-src" || name === "style-src" ? [HASH] : [];
    return [name, ...sources, ...extra].join(" ");
  }).join("; ");
}

function goodHeaders(overrides = {}) {
  const h = new Headers(PROD_HEADERS);
  h.set("content-security-policy-report-only", goodCsp());
  h.set("strict-transport-security", "max-age=300");
  for (const [k, v] of Object.entries(overrides)) {
    if (v === null) h.delete(k);
    else h.set(k, v);
  }
  return h;
}

test("parseHstsMaxAge", () => {
  assert.equal(parseHstsMaxAge("max-age=300"), 300);
  assert.equal(parseHstsMaxAge('max-age="31536000"; includeSubDomains'), 31536000);
  assert.equal(parseHstsMaxAge("max-age=1; max-age=2"), null);
  assert.equal(parseHstsMaxAge("max-age=abc"), null);
  assert.equal(parseHstsMaxAge(null), null);
});

test("cspProblems accepts hashes only in script-src and style-src", () => {
  assert.deepEqual(cspProblems(goodCsp()), []);
  assert.deepEqual(cspProblems(goodCsp().replace("img-src 'self'", `img-src 'self' ${HASH}`)), ["CSP directive img-src differs"]);
  assert.deepEqual(cspProblems(goodCsp().replace("default-src 'none'", "default-src *")), ["CSP directive default-src differs"]);
  assert.deepEqual(cspProblems(`${goodCsp()}; worker-src *`), ["CSP unexpected directive worker-src"]);
  assert.deepEqual(cspProblems(goodCsp().replace("; object-src 'none'", "")), ["CSP missing directive object-src"]);
  assert.deepEqual(cspProblems(null), ["content-security-policy-report-only missing"]);
  assert.deepEqual(cspProblems(`${goodCsp()}; default-src *`), ["CSP directive default-src repeated"]);
});

test("prodProblems flags missing or changed headers and low HSTS", () => {
  assert.deepEqual(prodProblems(goodHeaders()), []);
  const problems = prodProblems(
    goodHeaders({ "x-frame-options": "SAMEORIGIN", "referrer-policy": null, "strict-transport-security": "max-age=60" }),
  );
  assert.deepEqual(problems, ["referrer-policy missing", 'x-frame-options is "SAMEORIGIN"', "HSTS max-age=60 below 300"]);
});

test("run checks Prod fully and Beta HSTS only, with HEAD requests", async () => {
  const fetch = fakeFetch((url) => {
    if (url.hostname === "moyuri-kudo.com") return new Response(null, { status: 200, headers: goodHeaders() });
    return new Response(null, { status: 302, headers: { "strict-transport-security": "max-age=300" } });
  });
  const results = await run(makeCtx({ fetch }));
  assert.deepEqual(results.map((r) => [r.name, r.status]), [
    ["headers-prod", "PASS"],
    ["headers-beta-hsts", "PASS"],
  ]);
  assert.ok(fetch.calls.every((c) => c.init.method === "HEAD"));
  assert.equal(fetch.calls[0].url.searchParams.get("monitor"), String(NOW));
});

test("run fails Prod on a non-200 status and Beta without HSTS", async () => {
  const fetch = fakeFetch((url) =>
    url.hostname === "moyuri-kudo.com"
      ? new Response(null, { status: 500, headers: goodHeaders() })
      : new Response(null, { status: 302 }),
  );
  const [prod, beta] = await run(makeCtx({ fetch }));
  assert.equal(prod.status, "FAIL");
  assert.match(prod.detail, /status 500/);
  assert.equal(beta.status, "FAIL");
});

test("run reports request errors without messages", async () => {
  const fetch = fakeFetch(() => {
    throw Object.assign(new TypeError("fetch failed secret-ish"), { cause: { code: "ENOTFOUND" } });
  });
  const [prod] = await run(makeCtx({ fetch }));
  assert.equal(prod.detail, "TypeError (ENOTFOUND)");
});
