import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  CSP_HEADER,
  EXIT_FAIL,
  EXIT_HSTS_ONLY,
  EXIT_OK,
  HSTS_MIN_MAX_AGE,
  checkHeaders,
  classify,
  describeError,
  describeValue,
  expectedVersion,
  parseHstsMaxAge,
  resolveBaseUrl,
  run,
  waitForVersion,
} from "./smoke.mjs";

const SHA = "0123456789abcdef0123456789abcdef01234567";
const RUN_ID = "987654321";
const VERSION = `${SHA}-${RUN_ID}`;
const ENV = { GITHUB_SHA: SHA, GITHUB_RUN_ID: RUN_ID };
const CSP = "default-src 'none'; script-src 'self'; report-to csp";
const GOOD_HEADERS = {
  "x-content-type-options": "nosniff",
  "content-security-policy-report-only": CSP,
  "strict-transport-security": "max-age=300",
};
const GOOD_BODY = "<html><title>Moyuri Kudo</title></html>";

function fakeClock(start = 1_000_000) {
  let t = start;
  return {
    now: () => t,
    sleep: async (ms) => {
      t += ms;
    },
  };
}

function response(status, body, headers = {}) {
  return new Response(body, { status, headers });
}

/** Fake fetch: `versions` is the sequence of version.txt bodies, then `home` for "/". */
function fakeFetch({ versions, home }) {
  const calls = [];
  let i = 0;
  const impl = async (url, init) => {
    const u = new URL(url);
    calls.push({ path: u.pathname, search: u.search, init });
    if (u.pathname === "/version.txt") {
      const v = versions[Math.min(i, versions.length - 1)];
      i += 1;
      if (v instanceof Error) throw v;
      return response(200, `${v}\n`);
    }
    if (u.pathname === "/") return home();
    return response(404, "");
  };
  return { impl, calls };
}

describe("parseHstsMaxAge", () => {
  const cases = [
    ["max-age=300", 300],
    ["max-age=31536000; includeSubDomains; preload", 31536000],
    ["includeSubDomains; MAX-AGE=600", 600],
    ['max-age="300"', 300],
    ["  max-age = 300 ; preload", 300],
    ["max-age=0", 0],
    ["", null],
    [null, null],
    [undefined, null],
    ["includeSubDomains", null],
    ["max-age", null],
    ["max-age=", null],
    ["max-age=abc", null],
    ["max-age=-1", null],
    ["max-age=3.5", null],
    ["max-age=300; max-age=600", null],
    ["max-age=300, max-age=600", null],
    ["max-age=300; preload; preload", null],
    ['max-age="300', null],
  ];
  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} -> ${expected}`, () => {
      assert.equal(parseHstsMaxAge(input), expected);
    });
  }
});

describe("checkHeaders", () => {
  const h = (obj) => new Headers(Object.entries(obj).filter(([, v]) => v !== undefined));

  it("passes the baseline", () => {
    assert.deepEqual(checkHeaders(h(GOOD_HEADERS)), []);
  });

  it("accepts nosniff case-insensitively", () => {
    assert.deepEqual(checkHeaders(h({ ...GOOD_HEADERS, "x-content-type-options": " NoSniff " })), []);
  });

  it("fails a missing nosniff as a non-HSTS failure", () => {
    const f = checkHeaders(h({ ...GOOD_HEADERS, "x-content-type-options": undefined }));
    assert.deepEqual(f.map((x) => x.kind), ["header"]);
  });

  it("fails a wrong nosniff value", () => {
    const f = checkHeaders(h({ ...GOOD_HEADERS, "x-content-type-options": "sniff" }));
    assert.deepEqual(f.map((x) => x.kind), ["header"]);
  });

  it("fails a missing HSTS header as an HSTS failure", () => {
    const f = checkHeaders(h({ ...GOOD_HEADERS, "strict-transport-security": undefined }));
    assert.deepEqual(f.map((x) => x.kind), ["hsts"]);
  });

  it("accepts the Report-Only CSP with extra whitespace and case", () => {
    const csp = "  DEFAULT-SRC   'none' ; script-src 'self'";
    assert.deepEqual(checkHeaders(h({ ...GOOD_HEADERS, [CSP_HEADER]: csp })), []);
  });

  it("fails a missing Report-Only CSP as a non-HSTS failure", () => {
    const f = checkHeaders(h({ ...GOOD_HEADERS, [CSP_HEADER]: undefined }));
    assert.deepEqual(f.map((x) => x.kind), ["header"]);
  });

  it("fails a Report-Only CSP without default-src 'none'", () => {
    for (const csp of ["", "default-src 'self'", "script-src 'none'", "default-src 'none' 'self'"]) {
      const f = checkHeaders(h({ ...GOOD_HEADERS, [CSP_HEADER]: csp }));
      assert.deepEqual(f.map((x) => x.kind), ["header"], csp);
    }
  });

  it("does not accept an enforcing CSP in place of Report-Only", () => {
    const f = checkHeaders(h({ ...GOOD_HEADERS, [CSP_HEADER]: undefined, "content-security-policy": CSP }));
    assert.deepEqual(f.map((x) => x.kind), ["header"]);
  });

  it(`fails max-age below ${HSTS_MIN_MAX_AGE}`, () => {
    const f = checkHeaders(h({ ...GOOD_HEADERS, "strict-transport-security": "max-age=299" }));
    assert.deepEqual(f.map((x) => x.kind), ["hsts"]);
  });

  it(`passes max-age exactly ${HSTS_MIN_MAX_AGE}`, () => {
    assert.deepEqual(checkHeaders(h({ ...GOOD_HEADERS, "strict-transport-security": "max-age=300" })), []);
  });
});

describe("classify", () => {
  it("returns OK for no failures", () => {
    assert.equal(classify([]), EXIT_OK);
  });
  it("returns HSTS_ONLY when every failure is HSTS", () => {
    assert.equal(classify([{ kind: "hsts", message: "" }]), EXIT_HSTS_ONLY);
  });
  it("returns FAIL when any failure is not HSTS", () => {
    assert.equal(classify([{ kind: "hsts", message: "" }, { kind: "header", message: "" }]), EXIT_FAIL);
    assert.equal(classify([{ kind: "status", message: "" }]), EXIT_FAIL);
    assert.equal(classify([{ kind: "text", message: "" }]), EXIT_FAIL);
  });
});

describe("expectedVersion / resolveBaseUrl / describeValue", () => {
  it("builds <sha>-<run_id>", () => {
    assert.equal(expectedVersion(ENV), VERSION);
  });
  it("rejects a missing or malformed SHA or run ID", () => {
    assert.throws(() => expectedVersion({}));
    assert.throws(() => expectedVersion({ GITHUB_SHA: "abc", GITHUB_RUN_ID: RUN_ID }));
    assert.throws(() => expectedVersion({ GITHUB_SHA: SHA, GITHUB_RUN_ID: "12a" }));
  });
  it("defaults to the production origin", () => {
    assert.equal(resolveBaseUrl({}), "https://moyuri-kudo.com");
  });
  it("rejects a non-https override", () => {
    assert.throws(() => resolveBaseUrl({ SMOKE_BASE_URL: "http://example.com" }));
  });
  it("describes request errors with their cause code", () => {
    const err = Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNRESET" } });
    assert.equal(describeError(err), '"TypeError (ECONNRESET)"');
    assert.equal(describeError(new DOMException("t", "TimeoutError")), '"TimeoutError"');
    assert.equal(describeError(undefined), '"Error"');
  });
  it("escapes and truncates untrusted values", () => {
    assert.equal(describeValue("a\n::error::x"), '"a\\n::error::x"');
    assert.equal(describeValue(null), "(missing)");
    assert.ok(describeValue("x".repeat(200)).length < 100);
  });
});

describe("waitForVersion", () => {
  it("returns immediately when the first response matches", async () => {
    const clock = fakeClock();
    const { impl, calls } = fakeFetch({ versions: [VERSION] });
    const r = await waitForVersion({ baseUrl: "https://x.test", expected: VERSION, fetchImpl: impl, ...clock, log: () => {} });
    assert.deepEqual(r, { ok: true, attempts: 1 });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].init.cache, "no-store");
    assert.match(calls[0].search, /^\?smoke=/);
  });

  it("keeps polling until the version matches", async () => {
    const clock = fakeClock();
    const { impl } = fakeFetch({ versions: ["old", new Error("boom"), "old", VERSION] });
    const r = await waitForVersion({ baseUrl: "https://x.test", expected: VERSION, fetchImpl: impl, ...clock, log: () => {} });
    assert.deepEqual(r, { ok: true, attempts: 4 });
  });

  it("uses a different cache-busting query on every attempt", async () => {
    const clock = fakeClock();
    const { impl, calls } = fakeFetch({ versions: ["old", "old", VERSION] });
    await waitForVersion({ baseUrl: "https://x.test", expected: VERSION, fetchImpl: impl, ...clock, log: () => {} });
    assert.equal(new Set(calls.map((c) => c.search)).size, calls.length);
  });

  it("gives up after the timeout (10 s interval, 5 min limit)", async () => {
    const clock = fakeClock();
    const start = clock.now();
    const { impl, calls } = fakeFetch({ versions: ["old"] });
    const r = await waitForVersion({ baseUrl: "https://x.test", expected: VERSION, fetchImpl: impl, ...clock, log: () => {} });
    assert.equal(r.ok, false);
    assert.equal(r.attempts, 31);
    assert.equal(calls.length, 31);
    assert.equal(clock.now() - start, 300_000);
    assert.match(r.last, /old/);
  });

  it("does not accept a non-200 response even with a matching body", async () => {
    const clock = fakeClock();
    const impl = async () => response(404, VERSION);
    const r = await waitForVersion({
      baseUrl: "https://x.test",
      expected: VERSION,
      fetchImpl: impl,
      ...clock,
      log: () => {},
      timeoutMs: 20_000,
    });
    assert.equal(r.ok, false);
    assert.equal(r.attempts, 3);
  });
});

describe("run", () => {
  const quiet = () => {};

  it("passes when version, status, text and headers are good", async () => {
    const { impl } = fakeFetch({ versions: [VERSION], home: () => response(200, GOOD_BODY, GOOD_HEADERS) });
    assert.equal(await run({ env: ENV, fetchImpl: impl, ...fakeClock(), log: quiet }), EXIT_OK);
  });

  it("fails (rollback) when the version never matches", async () => {
    const { impl, calls } = fakeFetch({ versions: ["old"], home: () => response(200, GOOD_BODY, GOOD_HEADERS) });
    assert.equal(await run({ env: ENV, fetchImpl: impl, ...fakeClock(), log: quiet }), EXIT_FAIL);
    assert.ok(calls.every((c) => c.path === "/version.txt"));
  });

  it("fails (rollback) on a non-200 status", async () => {
    const { impl } = fakeFetch({ versions: [VERSION], home: () => response(500, GOOD_BODY, GOOD_HEADERS) });
    assert.equal(await run({ env: ENV, fetchImpl: impl, ...fakeClock(), log: quiet }), EXIT_FAIL);
  });

  it("fails (rollback) on a redirect", async () => {
    const { impl } = fakeFetch({
      versions: [VERSION],
      home: () => response(302, "", { ...GOOD_HEADERS, location: "https://elsewhere.test/" }),
    });
    assert.equal(await run({ env: ENV, fetchImpl: impl, ...fakeClock(), log: quiet }), EXIT_FAIL);
  });

  it("fails (rollback) when the text is missing", async () => {
    const { impl } = fakeFetch({ versions: [VERSION], home: () => response(200, "<html></html>", GOOD_HEADERS) });
    assert.equal(await run({ env: ENV, fetchImpl: impl, ...fakeClock(), log: quiet }), EXIT_FAIL);
  });

  it("fails (rollback) when GET / throws", async () => {
    const { impl } = fakeFetch({
      versions: [VERSION],
      home: () => {
        throw new TypeError("fetch failed");
      },
    });
    assert.equal(await run({ env: ENV, fetchImpl: impl, ...fakeClock(), log: quiet }), EXIT_FAIL);
  });

  it("returns HSTS_ONLY when only HSTS fails", async () => {
    const { impl } = fakeFetch({
      versions: [VERSION],
      home: () => response(200, GOOD_BODY, { ...GOOD_HEADERS, "strict-transport-security": "max-age=60" }),
    });
    assert.equal(await run({ env: ENV, fetchImpl: impl, ...fakeClock(), log: quiet }), EXIT_HSTS_ONLY);
  });

  it("fails (rollback) when HSTS and nosniff both fail", async () => {
    const { impl } = fakeFetch({ versions: [VERSION], home: () => response(200, GOOD_BODY, {}) });
    assert.equal(await run({ env: ENV, fetchImpl: impl, ...fakeClock(), log: quiet }), EXIT_FAIL);
  });

  it("fails (rollback) on a configuration error without any request", async () => {
    const { impl, calls } = fakeFetch({ versions: [VERSION], home: () => response(200, GOOD_BODY, GOOD_HEADERS) });
    assert.equal(await run({ env: { GITHUB_SHA: SHA }, fetchImpl: impl, ...fakeClock(), log: quiet }), EXIT_FAIL);
    assert.equal(calls.length, 0);
  });
});
