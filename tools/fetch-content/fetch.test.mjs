import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  FetchContentError,
  MAX_ATTEMPTS,
  countUnpublished,
  parseCli,
  readConfig,
  run,
} from "./fetch.mjs";

const SCRIPT = fileURLToPath(new URL("./fetch.mjs", import.meta.url));
const SERVICE = "svc-test";
const PUB_KEY = "PUBKEY_SENTINEL_aaaaaaaa";
const DRAFT_KEY = "DRAFTKEY_SENTINEL_bbbbbbbb";
const SECRET_TITLE = "TITLE_SENTINEL_cccc";
const TS = "2026-01-01T00:00:00.000Z";

function sys(id, published = true) {
  const base = { id, createdAt: TS, updatedAt: TS };
  return published ? { ...base, publishedAt: TS, revisedAt: TS } : base;
}

function category(n, published = true) {
  return { ...sys(`cat${n}`, published), name: `${SECRET_TITLE}-c${n}`, slug: `c${n}` };
}

function project(n, opts = {}) {
  return {
    ...sys(`p${n}`, opts.published ?? true),
    title: `${SECRET_TITLE}-p${n}`,
    slug: `p${n}`,
    cover: { url: "https://images.microcms-assets.io/a.png", width: 10, height: 10 },
    category: opts.category ?? category(1),
  };
}

function objectApi(published = true) {
  const base = { createdAt: TS, updatedAt: TS, tagline: SECRET_TITLE };
  return published ? { ...base, publishedAt: TS, revisedAt: TS } : base;
}

function jsonResponse(status, body, headers = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

/**
 * Builds a mock fetch over in-memory data.
 * data: { categories: [...], projects: [...], profile: {...}, site: {...} }
 * hooks: optional (endpoint, url, callIndex) => Response | undefined to override.
 */
function mockFetch(data, hooks) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    const u = new URL(url);
    const endpoint = u.pathname.replace("/api/v1/", "");
    const override = hooks?.(endpoint, u, calls.length);
    if (override) return override;
    const value = data[endpoint];
    if (Array.isArray(value)) {
      const limit = Number(u.searchParams.get("limit"));
      const offset = Number(u.searchParams.get("offset"));
      return jsonResponse(200, {
        contents: value.slice(offset, offset + limit),
        totalCount: value.length,
        offset,
        limit,
      });
    }
    if (value) return jsonResponse(200, value);
    return jsonResponse(404, { message: "not found" });
  };
  return { fetchImpl, calls };
}

function baseData(overrides = {}) {
  return {
    categories: [category(1), category(2)],
    projects: [project(1), project(2)],
    profile: objectApi(),
    site: objectApi(),
    ...overrides,
  };
}

const ENV_PUBLISHED = { MICROCMS_SERVICE_ID: SERVICE, MICROCMS_API_KEY_PUBLISHED: PUB_KEY };
const ENV_DRAFT = { MICROCMS_SERVICE_ID: SERVICE, MICROCMS_API_KEY_DRAFT: DRAFT_KEY };

let workDir;
before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "fetch-content-test-"));
});
after(async () => {
  await rm(workDir, { recursive: true, force: true });
});

let outCounter = 0;
function newOut() {
  outCounter += 1;
  return path.join(workDir, `out${outCounter}`);
}

async function runWith({
  mode = "published",
  env = ENV_PUBLISHED,
  data = baseData(),
  hooks,
  fetchOverride,
  timeoutMs,
  out = newOut(),
} = {}) {
  const mocked = mockFetch(data, hooks);
  const calls = mocked.calls;
  const fetchImpl = fetchOverride ?? mocked.fetchImpl;
  const logs = [];
  const sleeps = [];
  let error;
  try {
    await run({
      mode,
      out,
      env,
      fetchImpl,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
      log: (line) => logs.push(line),
      timeoutMs,
    });
  } catch (err) {
    error = err;
  }
  return { calls, logs, sleeps, out, error };
}

function assertNoSecrets(text) {
  for (const s of [PUB_KEY, DRAFT_KEY, SECRET_TITLE, "microcms.io", "https://"]) {
    assert.ok(!text.includes(s), `output leaked ${s}: ${text}`);
  }
}

describe("parseCli", () => {
  it("accepts both modes", () => {
    assert.deepEqual(parseCli(["--mode", "draft", "--out", "x"]), { mode: "draft", out: "x" });
    assert.deepEqual(parseCli(["--mode=published", "--out=y"]), { mode: "published", out: "y" });
  });
  it("rejects bad input", () => {
    assert.throws(() => parseCli(["--mode", "all", "--out", "x"]), FetchContentError);
    assert.throws(() => parseCli(["--mode", "draft"]), FetchContentError);
    assert.throws(() => parseCli(["--mode", "draft", "--out", "x", "extra"]), FetchContentError);
    assert.throws(() => parseCli(["--unknown"]), FetchContentError);
  });
});

describe("readConfig", () => {
  it("uses only the key for the mode", () => {
    const both = { ...ENV_PUBLISHED, MICROCMS_API_KEY_DRAFT: DRAFT_KEY };
    assert.equal(readConfig("published", both).apiKey, PUB_KEY);
    assert.equal(readConfig("draft", both).apiKey, DRAFT_KEY);
  });
  it("never falls back to the other key", () => {
    assert.throws(() => readConfig("published", ENV_DRAFT), /MICROCMS_API_KEY_PUBLISHED/);
    assert.throws(() => readConfig("draft", ENV_PUBLISHED), /MICROCMS_API_KEY_DRAFT/);
  });
  it("validates the service ID", () => {
    for (const bad of ["", "ab", "UPPER", "a.b.c", "evil.com/x", "x".repeat(33)]) {
      assert.throws(
        () => readConfig("published", { ...ENV_PUBLISHED, MICROCMS_SERVICE_ID: bad }),
        /MICROCMS_SERVICE_ID/,
      );
    }
  });
  it("rejects keys with whitespace or control characters without echoing them", () => {
    try {
      readConfig("published", { ...ENV_PUBLISHED, MICROCMS_API_KEY_PUBLISHED: `${PUB_KEY}\n` });
      assert.fail("expected throw");
    } catch (err) {
      assert.ok(err instanceof FetchContentError);
      assertNoSecrets(err.message);
    }
  });
});

describe("run", () => {
  it("writes one file per endpoint and logs counts only", async () => {
    const r = await runWith();
    assert.equal(r.error, undefined);
    assert.deepEqual((await readdir(r.out)).sort(), [
      "categories.json",
      "profile.json",
      "projects.json",
      "site.json",
    ]);
    const projects = JSON.parse(await readFile(path.join(r.out, "projects.json"), "utf8"));
    assert.equal(projects.totalCount, 2);
    assert.deepEqual(
      projects.contents.map((p) => p.id),
      ["p1", "p2"],
    );
    const site = JSON.parse(await readFile(path.join(r.out, "site.json"), "utf8"));
    assert.equal(site.tagline, SECRET_TITLE);
    assert.deepEqual(r.logs, [
      "categories: 2 items",
      "projects: 2 items",
      "profile: 1 object",
      "site: 1 object",
    ]);
  });

  it("sends the key header, no redirects, and only limit/offset", async () => {
    const r = await runWith();
    assert.equal(r.calls.length, 4);
    for (const { url, init } of r.calls) {
      const u = new URL(url);
      assert.equal(u.origin, `https://${SERVICE}.microcms.io`);
      for (const key of u.searchParams.keys()) assert.ok(["limit", "offset"].includes(key), key);
      assert.equal(init.headers["X-MICROCMS-API-KEY"], PUB_KEY);
      assert.equal(init.redirect, "error");
      assert.ok(init.signal instanceof AbortSignal);
    }
  });

  it("is deterministic across runs", async () => {
    const a = await runWith();
    const b = await runWith();
    for (const f of ["categories.json", "projects.json", "profile.json", "site.json"]) {
      assert.equal(
        await readFile(path.join(a.out, f), "utf8"),
        await readFile(path.join(b.out, f), "utf8"),
      );
    }
  });

  it("paginates until totalCount", async () => {
    const projects = Array.from({ length: 250 }, (_, i) => project(i));
    const r = await runWith({ data: baseData({ projects }) });
    assert.equal(r.error, undefined);
    const offsets = r.calls
      .filter((c) => new URL(c.url).pathname.endsWith("/projects"))
      .map((c) => new URL(c.url).searchParams.get("offset"));
    assert.deepEqual(offsets, ["0", "100", "200"]);
    const written = JSON.parse(await readFile(path.join(r.out, "projects.json"), "utf8"));
    assert.equal(written.contents.length, 250);
    assert.equal(written.contents[249].id, "p249");
    assert.ok(r.logs.includes("projects: 250 items"));
  });

  it("handles empty lists with a single request", async () => {
    const r = await runWith({ data: baseData({ categories: [], projects: [] }) });
    assert.equal(r.error, undefined);
    assert.equal(r.calls.length, 4);
  });

  it("fails when a page is empty before totalCount", async () => {
    const r = await runWith({
      hooks: (ep, u) =>
        ep === "projects" && u.searchParams.get("offset") === "0"
          ? jsonResponse(200, { contents: [], totalCount: 5 })
          : undefined,
    });
    assert.match(r.error.message, /projects: page is empty/);
  });

  it("fails when totalCount changes mid-pagination", async () => {
    const projects = Array.from({ length: 150 }, (_, i) => project(i));
    const r = await runWith({
      data: baseData({ projects }),
      hooks: (ep, u) =>
        ep === "projects" && u.searchParams.get("offset") === "100"
          ? jsonResponse(200, { contents: [project(200)], totalCount: 151 })
          : undefined,
    });
    assert.match(r.error.message, /totalCount changed/);
  });

  it("fails on duplicate ids", async () => {
    const r = await runWith({ data: baseData({ projects: [project(1), project(1)] }) });
    assert.match(r.error.message, /duplicate item id/);
  });

  it("fails on structural errors", async () => {
    const cases = [
      [{ items: [] }, /no contents array/],
      [{ contents: [{ title: "x" }], totalCount: 1 }, /without a string id/],
      [{ contents: [], totalCount: -1 }, /totalCount is invalid/],
      [{ contents: [], totalCount: "3" }, /totalCount is invalid/],
    ];
    for (const [body, re] of cases) {
      const r = await runWith({
        hooks: (ep) => (ep === "categories" ? jsonResponse(200, body) : undefined),
      });
      assert.match(r.error.message, re);
    }
    const arr = await runWith({ hooks: (ep) => (ep === "site" ? jsonResponse(200, []) : undefined) });
    assert.match(arr.error.message, /site: response is not an object/);
  });

  it("retries 429 and 5xx up to the bound, honoring Retry-After", async () => {
    let n = 0;
    const r = await runWith({
      hooks: (ep) => {
        if (ep !== "categories") return undefined;
        n += 1;
        if (n === 1) return jsonResponse(429, { message: SECRET_TITLE }, { "retry-after": "2" });
        if (n === 2) return jsonResponse(503, { message: SECRET_TITLE });
        return undefined;
      },
    });
    assert.equal(r.error, undefined);
    assert.deepEqual(r.sleeps, [2000, 2000]);
    assert.ok(r.logs.includes("categories: HTTP 429, retrying (1/2)"));
    assertNoSecrets(r.logs.join("\n"));
  });

  it("gives up after MAX_ATTEMPTS on persistent 5xx", async () => {
    let n = 0;
    const r = await runWith({
      hooks: (ep) => {
        if (ep !== "projects") return undefined;
        n += 1;
        return jsonResponse(500, { message: SECRET_TITLE });
      },
    });
    assert.equal(n, MAX_ATTEMPTS);
    assert.equal(r.error.message, "projects: HTTP 500");
  });

  it("does not retry other 4xx", async () => {
    for (const [endpoint, status] of [
      ["profile", 400],
      ["profile", 401],
      ["profile", 403],
      ["projects", 404],
      ["categories", 404],
    ]) {
      let n = 0;
      const r = await runWith({
        hooks: (ep) => {
          if (ep !== endpoint) return undefined;
          n += 1;
          return jsonResponse(status, { message: SECRET_TITLE });
        },
      });
      assert.equal(n, 1);
      assert.equal(r.error.message, `${endpoint}: HTTP ${status}`);
      assert.deepEqual(r.sleeps, []);
    }
  });

  it("writes null for an object API that answers 404, in both modes", async () => {
    for (const [mode, env] of [
      ["published", ENV_PUBLISHED],
      ["draft", ENV_DRAFT],
    ]) {
      const r = await runWith({ mode, env, data: baseData({ profile: undefined, site: undefined }) });
      assert.equal(r.error, undefined);
      for (const f of ["profile.json", "site.json"]) {
        assert.equal(await readFile(path.join(r.out, f), "utf8"), "null\n");
      }
      assert.deepEqual(r.logs.slice(2), ["profile: no content (404)", "site: no content (404)"]);
      assert.equal(r.calls.length, 4);
      assert.deepEqual(r.sleeps, []);
    }
  });

  it("builds an empty result when nothing is published", async () => {
    const r = await runWith({
      data: { categories: [], projects: [], profile: undefined, site: undefined },
    });
    assert.equal(r.error, undefined);
    const projects = JSON.parse(await readFile(path.join(r.out, "projects.json"), "utf8"));
    assert.deepEqual(projects, { contents: [], totalCount: 0 });
    assert.equal(JSON.parse(await readFile(path.join(r.out, "site.json"), "utf8")), null);
  });

  it("reports network errors by name only", async () => {
    const r = await runWith({
      hooks: (ep) => {
        if (ep !== "categories") return undefined;
        const err = new TypeError(`fetch failed https://${SERVICE}.microcms.io ${PUB_KEY}`);
        err.cause = Object.assign(new Error(PUB_KEY), { code: "ECONNRESET" });
        throw err;
      },
    });
    assert.equal(r.error.message, "categories: request failed: TypeError (ECONNRESET)");
  });

  it("fails on invalid JSON without printing the body", async () => {
    const r = await runWith({
      hooks: (ep) => (ep === "site" ? new Response(`<html>${SECRET_TITLE}`, { status: 200 }) : undefined),
    });
    assert.equal(r.error.message, "site: response is not valid JSON");
  });

  it("times out a hanging request without retrying", async () => {
    let n = 0;
    const hanging = (url, init) => {
      n += 1;
      return new Promise((_, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason));
      });
    };
    const r = await runWith({ fetchOverride: hanging, timeoutMs: 20 });
    assert.equal(n, 1);
    assert.equal(r.error.message, "categories: request failed: TimeoutError");
  });

  it("reports a body read timeout as a timeout", async () => {
    const stalled = async (url, init) => {
      const body = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("{"));
          init.signal.addEventListener("abort", () => controller.error(init.signal.reason));
        },
      });
      return new Response(body, { status: 200 });
    };
    const r = await runWith({ fetchOverride: stalled, timeoutMs: 20 });
    assert.equal(r.error.message, "categories: request failed: TimeoutError");
  });

  it("accepts an existing empty out dir and rejects a non-empty one", async () => {
    const empty = newOut();
    await mkdir(empty);
    assert.equal((await runWith({ out: empty })).error, undefined);
    const dirty = newOut();
    await mkdir(dirty);
    await writeFile(path.join(dirty, "stale.json"), "{}");
    const r = await runWith({ out: dirty });
    assert.equal(r.error.message, "--out must be an empty directory or not exist");
    assert.equal(r.calls.length, 0);
    assert.deepEqual(await readdir(dirty), ["stale.json"]);
  });

  it("writes nothing when any endpoint fails", async () => {
    const r = await runWith({
      hooks: (ep) => (ep === "site" ? jsonResponse(500, {}) : undefined),
    });
    assert.ok(r.error);
    await assert.rejects(readdir(r.out), { code: "ENOENT" });
  });
});

describe("published assertion", () => {
  it("fails on an unpublished list item", async () => {
    const r = await runWith({ data: baseData({ projects: [project(1), project(2, { published: false })] }) });
    assert.equal(r.error.message, "projects: 1 unpublished content object(s) in published mode");
    assertNoSecrets(r.error.message);
  });

  it("fails on an unpublished embedded relation", async () => {
    const r = await runWith({
      data: baseData({ projects: [project(1, { category: category(9, false) })] }),
    });
    assert.match(r.error.message, /^projects: 1 unpublished/);
  });

  it("fails on an unpublished object API", async () => {
    const r = await runWith({ data: baseData({ profile: objectApi(false) }) });
    assert.match(r.error.message, /^profile: 1 unpublished/);
  });

  it("treats empty publishedAt as unpublished", async () => {
    const p = { ...project(1), publishedAt: "" };
    const r = await runWith({ data: baseData({ projects: [p] }) });
    assert.match(r.error.message, /^projects: 1 unpublished/);
  });

  it("is not applied in draft mode", async () => {
    const r = await runWith({
      mode: "draft",
      env: ENV_DRAFT,
      data: baseData({
        projects: [project(1, { published: false, category: category(3, false) })],
        site: objectApi(false),
      }),
    });
    assert.equal(r.error, undefined);
    for (const { init } of r.calls) assert.equal(init.headers["X-MICROCMS-API-KEY"], DRAFT_KEY);
  });

  it("countUnpublished ignores media and null relations", () => {
    const p = { ...project(1), category: null };
    assert.equal(countUnpublished(p), 0);
    assert.equal(countUnpublished({ ...p, cover: { url: "https://x" } }), 0);
  });
});

describe("CLI", () => {
  function cli(args, env) {
    return spawnSync(process.execPath, [SCRIPT, ...args], {
      env: { PATH: process.env.PATH, ...env },
      encoding: "utf8",
      timeout: 10_000,
    });
  }

  it("exits 1 with a fixed message when the mode's key is missing", () => {
    const r = cli(["--mode", "published", "--out", path.join(workDir, "cli1")], ENV_DRAFT);
    assert.equal(r.status, 1);
    assert.equal(r.stdout, "");
    assert.equal(r.stderr, "fetch-content: error: MICROCMS_API_KEY_PUBLISHED is missing or invalid\n");
    assertNoSecrets(r.stderr);
  });

  it("exits 1 on an invalid service ID without echoing it or the key", () => {
    const r = cli(["--mode", "draft", "--out", path.join(workDir, "cli2")], {
      ...ENV_DRAFT,
      MICROCMS_SERVICE_ID: `bad.${SECRET_TITLE}`,
    });
    assert.equal(r.status, 1);
    assert.equal(r.stderr, "fetch-content: error: MICROCMS_SERVICE_ID is missing or invalid\n");
    assertNoSecrets(r.stderr);
  });

  it("exits 1 on bad arguments", () => {
    const r = cli(["--mode", "both"], ENV_PUBLISHED);
    assert.equal(r.status, 1);
    assert.equal(r.stderr, "fetch-content: error: --mode must be published or draft\n");
  });
});
