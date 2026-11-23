// Tests for key-expiry, the D1 CSP checks and the GitHub checks.

import assert from "node:assert/strict";
import { test } from "node:test";
import { KEYS, RULESET } from "../config.mjs";
import { DAY_MS } from "../lib.mjs";
import { NOW, fakeFetch, files, json, makeCtx } from "../test-helpers.mjs";
import { databaseId, run as runCsp } from "./csp-d1.mjs";
import { nextLink, parseTokenExpiration, rulesetProblems, run as runGithub } from "./github.mjs";
import { keyProblems, run as runKeys } from "./key-expiry.mjs";

const statuses = (results) => results.map((r) => r.status);
const day = (n) => new Date(NOW + n * DAY_MS).toISOString().slice(0, 10);
const allKeys = (date = day(365)) => Object.fromEntries(KEYS.map((k) => [k, date]));

// key-expiry

test("keyProblems: all present and far, missing, near, invalid, unknown", () => {
  assert.deepEqual(keyProblems(allKeys(), NOW), []);
  const { K4: _k4, ...withoutK4 } = allKeys();
  assert.deepEqual(keyProblems(withoutK4, NOW), ["K4 missing"]);
  assert.deepEqual(keyProblems({ ...allKeys(), K9: day(29) }, NOW), ["K9 28 day(s) left"]);
  assert.deepEqual(keyProblems({ ...allKeys(), K1: "2027-02-30" }, NOW), ['K1 has invalid date "2027-02-30"']);
  assert.deepEqual(keyProblems({ ...allKeys(), K8: day(100) }, NOW), ['unknown key "K8"']);
  assert.deepEqual(keyProblems([], NOW), ["not a JSON object"]);
});

test("key-expiry run reads the repo file", async () => {
  const ok = await runKeys(makeCtx({ readFile: files({ "tools/monitor/key-expiry.json": JSON.stringify(allKeys()) }) }));
  assert.equal(ok[0].status, "PASS");
  const broken = await runKeys(makeCtx({ readFile: files({ "tools/monitor/key-expiry.json": "{" }) }));
  assert.equal(broken[0].status, "FAIL");
  assert.equal(broken[0].detail, "SyntaxError");
});

// csp-d1

const DB_ID = "0123abcd-0123-4abc-8def-0123456789ab";
const ACCOUNT = "0123456789abcdef0123456789abcdef";
const wrangler = (id) => `{
  // csp-report Worker
  "$schema": "https://example.com/schema.json",
  "name": "csp-report",
  "d1_databases": [
    { "binding": "DB", "database_name": "csp_reports", "database_id": "${id}", },
  ],
}`;

test("databaseId parses JSONC and handles the placeholder", () => {
  assert.deepEqual(databaseId(wrangler(DB_ID)), { id: DB_ID });
  assert.deepEqual(databaseId(wrangler("<d1-database-id>")), { skip: "database_id not set" });
  assert.deepEqual(databaseId('{"name":"csp-report"}'), { skip: "database_id not set" });
  assert.throws(() => databaseId(wrangler("not-a-uuid")), TypeError);
});

test("csp-d1 skips when the config is absent or has the placeholder", async () => {
  assert.deepEqual(statuses(await runCsp(makeCtx())), ["SKIP", "SKIP"]);
  const placeholder = files({ "apps/csp-report/wrangler.jsonc": wrangler("<d1-database-id>") });
  assert.deepEqual(statuses(await runCsp(makeCtx({ readFile: placeholder, requireCredentials: true }))), ["SKIP", "SKIP"]);
});

test("csp-d1 skips without a token, fails when credentials are required", async () => {
  const readFile = files({ "apps/csp-report/wrangler.jsonc": wrangler(DB_ID) });
  assert.deepEqual(statuses(await runCsp(makeCtx({ readFile }))), ["SKIP", "SKIP"]);
  assert.deepEqual(statuses(await runCsp(makeCtx({ readFile, requireCredentials: true }))), ["FAIL", "FAIL"]);
  const badAccount = { CLOUDFLARE_API_TOKEN: "t", CLOUDFLARE_ACCOUNT_ID: "../x" };
  assert.deepEqual(statuses(await runCsp(makeCtx({ readFile, env: badAccount }))), ["FAIL", "FAIL"]);
});

test("csp-d1 queries D1 with bound parameters and counts", async () => {
  const readFile = files({ "apps/csp-report/wrangler.jsonc": wrangler(DB_ID) });
  const env = { CLOUDFLARE_API_TOKEN: "token-value", CLOUDFLARE_ACCOUNT_ID: ACCOUNT };
  const counts = [0, 3];
  const fetch = fakeFetch(() => json({ success: true, result: [{ success: true, results: [{ n: counts.shift() }] }] }));
  const results = await runCsp(makeCtx({ readFile, env, fetch }));
  assert.deepEqual(statuses(results), ["PASS", "FAIL"]);
  assert.equal(results[1].detail, "3 overflow report(s) since 2026-11-23");
  const [first, second] = fetch.calls;
  assert.equal(first.url.href, `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/d1/database/${DB_ID}/query`);
  assert.equal(first.init.method, "POST");
  assert.equal(first.init.headers.authorization, "Bearer token-value");
  assert.deepEqual(JSON.parse(first.init.body).params, [Date.parse("2026-11-23T00:00:00Z")]);
  assert.deepEqual(JSON.parse(second.init.body).params, ["2026-11-23"]);
  assert.ok(!results.some((r) => r.detail.includes("token-value")));
});

test("csp-d1 fails on API errors and malformed responses", async () => {
  const readFile = files({ "apps/csp-report/wrangler.jsonc": wrangler(DB_ID) });
  const env = { CLOUDFLARE_API_TOKEN: "t", CLOUDFLARE_ACCOUNT_ID: ACCOUNT };
  const denied = await runCsp(makeCtx({ readFile, env, fetch: fakeFetch(() => json({ success: false }, 403)) }));
  assert.deepEqual(denied.map((r) => r.detail), ["HttpError (status 403)", "HttpError (status 403)"]);
  const odd = await runCsp(makeCtx({ readFile, env, fetch: fakeFetch(() => json({ success: true, result: [] })) }));
  assert.deepEqual(statuses(odd), ["FAIL", "FAIL"]);
});

// github

test("parseTokenExpiration", () => {
  assert.equal(parseTokenExpiration("2027-11-24 07:00:00 UTC").toISOString(), "2027-11-24T07:00:00.000Z");
  assert.equal(parseTokenExpiration("2027-11-24 07:00:00 +0900").toISOString(), "2027-11-23T22:00:00.000Z");
  assert.equal(parseTokenExpiration("never"), null);
  assert.equal(parseTokenExpiration(null), null);
});

test("nextLink follows only api.github.com", () => {
  const link = '<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"';
  assert.equal(nextLink(link).href, "https://api.github.com/x?page=2");
  assert.equal(nextLink('<https://evil.example/x>; rel="next"'), null);
  assert.equal(nextLink(null), null);
});

function goodRuleset() {
  return {
    id: 26758407,
    name: "main",
    target: "branch",
    enforcement: "active",
    conditions: { ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] } },
    current_user_can_bypass: "never",
    rules: [
      { type: "deletion" },
      { type: "non_fast_forward" },
      { type: "required_linear_history" },
      { type: "required_signatures" },
      { type: "pull_request", parameters: { ...RULESET.pullRequest, required_reviewers: [], require_extra_approval_for_unattributed_changes: true } },
      {
        type: "required_status_checks",
        parameters: {
          strict_required_status_checks_policy: true,
          do_not_enforce_on_create: false,
          required_status_checks: RULESET.statusChecks.contexts.map((context) => ({ context, integration_id: 15368 })),
        },
      },
    ],
  };
}

test("rulesetProblems: matches, and detects drift", () => {
  assert.deepEqual(rulesetProblems(goodRuleset()), []);
  assert.deepEqual(rulesetProblems({ ...goodRuleset(), enforcement: "disabled" }), ["enforcement"]);
  assert.deepEqual(rulesetProblems({ ...goodRuleset(), bypass_actors: [{ actor_id: 5 }] }), ["bypass_actors"]);
  assert.deepEqual(rulesetProblems({ ...goodRuleset(), bypass_actors: [] }), []);
  assert.deepEqual(rulesetProblems({ ...goodRuleset(), current_user_can_bypass: "always" }), ["current_user_can_bypass"]);
  const { current_user_can_bypass: _c, ...noBypassField } = goodRuleset();
  assert.deepEqual(rulesetProblems(noBypassField), ["current_user_can_bypass"]);
  const noSig = goodRuleset();
  noSig.rules = noSig.rules.filter((r) => r.type !== "required_signatures");
  assert.deepEqual(rulesetProblems(noSig), ["rule types"]);
  const approvals = goodRuleset();
  approvals.rules[4].parameters.allowed_merge_methods = ["squash", "merge"];
  assert.deepEqual(rulesetProblems(approvals), ["pull_request.allowed_merge_methods"]);
  const checks = goodRuleset();
  checks.rules[5].parameters.required_status_checks.pop();
  checks.rules[5].parameters.strict_required_status_checks_policy = false;
  assert.deepEqual(rulesetProblems(checks), ["required_status_checks.strict", "required_status_checks.contexts"]);
  const app = goodRuleset();
  app.rules[5].parameters.required_status_checks[0].integration_id = 1;
  assert.deepEqual(rulesetProblems(app), ["required_status_checks.integration_id"]);
});

function githubFetch({ expiration = "2027-11-24 07:00:00 UTC", alerts = [], collaborators = [{ login: "takeru-kudo" }], ruleset = goodRuleset(), rulesets } = {}) {
  return fakeFetch((url) => {
    const p = url.pathname;
    if (p === "/repos/takeru-kudo/moyuri-portfolio") {
      return json({}, 200, expiration ? { "github-authentication-token-expiration": expiration } : {});
    }
    if (p.endsWith("/dependabot/alerts")) return json(alerts);
    if (p.endsWith("/collaborators")) return json(collaborators);
    if (p.endsWith("/rulesets")) return json(rulesets ?? [{ id: ruleset.id, name: "main" }]);
    if (p.endsWith(`/rulesets/${ruleset.id}`)) return json(ruleset);
    return json({}, 404);
  });
}

const keyFile = (k9 = "2027-11-24") => files({ "tools/monitor/key-expiry.json": JSON.stringify({ ...allKeys(), K9: k9 }) });

test("github: skip without token, fail when required", async () => {
  assert.deepEqual(statuses(await runGithub(makeCtx())), ["SKIP", "SKIP", "SKIP", "SKIP"]);
  assert.deepEqual(statuses(await runGithub(makeCtx({ requireCredentials: true }))), ["FAIL", "FAIL", "FAIL", "FAIL"]);
});

test("github: all pass and the token is sent but never reported", async () => {
  const fetch = githubFetch();
  const env = { MONITOR_GITHUB_TOKEN: "ghp-secret" };
  const results = await runGithub(makeCtx({ env, fetch, readFile: keyFile() }));
  assert.deepEqual(statuses(results), ["PASS", "PASS", "PASS", "PASS"]);
  assert.ok(fetch.calls.every((c) => c.init.headers.authorization === "Bearer ghp-secret"));
  assert.ok(!results.some((r) => r.detail.includes("ghp-secret")));
  const alertsCall = fetch.calls.find((c) => c.url.pathname.endsWith("/dependabot/alerts"));
  assert.equal(alertsCall.url.searchParams.get("severity"), "high,critical");
  assert.equal(alertsCall.url.searchParams.get("state"), "open");
});

test("github: token expiry near, missing header, differing record", async () => {
  const env = { MONITOR_GITHUB_TOKEN: "t" };
  const near = await runGithub(makeCtx({ env, fetch: githubFetch({ expiration: "2026-12-20 00:00:00 UTC" }), readFile: keyFile("2026-12-20") }));
  assert.equal(near[0].status, "FAIL");
  const none = await runGithub(makeCtx({ env, fetch: githubFetch({ expiration: null }), readFile: keyFile() }));
  assert.equal(none[0].detail, "expiration header missing or invalid");
  const differs = await runGithub(makeCtx({ env, fetch: githubFetch(), readFile: keyFile("2027-10-01") }));
  assert.match(differs[0].detail, /differs from the K9 date/);
});

test("github: stale alerts, extra collaborators, missing ruleset", async () => {
  const env = { MONITOR_GITHUB_TOKEN: "t" };
  const alerts = [
    { created_at: new Date(NOW - 8 * DAY_MS).toISOString() },
    { created_at: new Date(NOW - 2 * DAY_MS).toISOString() },
  ];
  const results = await runGithub(
    makeCtx({
      env,
      readFile: keyFile(),
      fetch: githubFetch({ alerts, collaborators: [{ login: "takeru-kudo" }, { login: "someone" }], rulesets: [] }),
    }),
  );
  assert.deepEqual(statuses(results), ["PASS", "FAIL", "FAIL", "FAIL"]);
  assert.equal(results[1].detail, "2 open high/critical, 1 open 7+ day(s)");
  assert.equal(results[2].detail, "1 collaborator(s) besides the owner");
  assert.equal(results[3].detail, "ruleset main not found");
});

test("github: API errors fail each check separately", async () => {
  const env = { MONITOR_GITHUB_TOKEN: "t" };
  const results = await runGithub(makeCtx({ env, readFile: keyFile(), fetch: fakeFetch(() => json({}, 403)) }));
  assert.deepEqual(results.map((r) => r.detail), Array(4).fill("HttpError (status 403)"));
});

test("github: follows pagination", async () => {
  const env = { MONITOR_GITHUB_TOKEN: "t" };
  const base = githubFetch();
  const fetch = fakeFetch((url, init) => {
    if (url.pathname.endsWith("/collaborators") && url.searchParams.get("page") !== "2") {
      return json([{ login: "takeru-kudo" }], 200, { link: `<${url.origin}${url.pathname}?page=2>; rel="next"` });
    }
    if (url.pathname.endsWith("/collaborators")) return json([{ login: "intruder" }]);
    return base(url, init);
  });
  const results = await runGithub(makeCtx({ env, readFile: keyFile(), fetch }));
  assert.equal(results[2].status, "FAIL");
});
