import { createExecutionContext, createScheduledController, waitOnExecutionContext } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_BODY_BYTES } from "../src/body.ts";
import worker, { MAX_KEYS_PER_REQUEST } from "../src/index.ts";
import { DAILY_NEW_ROW_CAP } from "../src/store.ts";

const ORIGIN = "https://moyuri-kudo.com";
const URL_REPORT = "https://csp.moyuri-kudo.com/report";
const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 10, 24, 12, 0, 0);

interface Row {
  directive: string;
  blocked_origin: string;
  document_path: string;
  count: number;
  first_seen: number;
  last_seen: number;
}

beforeEach(async () => {
  await env.DB.batch([env.DB.prepare("DELETE FROM violations"), env.DB.prepare("DELETE FROM overflow")]);
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function violation(blockedURL: string, documentURL = `${ORIGIN}/works/a?x=1`, effectiveDirective = "script-src-elem") {
  return { type: "csp-violation", age: 0, url: documentURL, body: { documentURL, blockedURL, effectiveDirective } };
}

function reportRequest(body: string | Uint8Array, contentType = "application/reports+json", headers: HeadersInit = {}) {
  return new Request(URL_REPORT, {
    method: "POST",
    headers: { "Content-Type": contentType, Origin: ORIGIN, ...headers },
    body,
  });
}

async function send(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const res = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

async function rows(): Promise<Row[]> {
  const { results } = await env.DB.prepare(
    "SELECT * FROM violations ORDER BY directive, blocked_origin, document_path",
  ).all<Row>();
  return results;
}

async function overflowCount(day = "2026-11-24"): Promise<number> {
  const row = await env.DB.prepare("SELECT count FROM overflow WHERE day = ?1").bind(day).first<{ count: number }>();
  return row?.count ?? 0;
}

describe("paths and methods", () => {
  it("GET /healthz returns the version ID from the binding", async () => {
    const res = await exports.default.fetch("https://csp.moyuri-kudo.com/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok", version: env.CF_VERSION_METADATA.id });
  });

  it.each(["/", "/report/", "/REPORT", "/healthz/x", "/favicon.ico"])("404 for %s", async (path) => {
    const res = await send(new Request(`https://csp.moyuri-kudo.com${path}`, { method: "POST" }));
    expect(res.status).toBe(404);
  });

  it.each([
    ["GET", "/report", "POST, OPTIONS"],
    ["PUT", "/report", "POST, OPTIONS"],
    ["POST", "/healthz", "GET"],
  ])("405 for %s %s", async (method, path, allow) => {
    const res = await send(new Request(`https://csp.moyuri-kudo.com${path}`, { method }));
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe(allow);
  });
});

describe("CORS", () => {
  function preflight(origin: string | null, method = "POST") {
    const headers = new Headers({ "Access-Control-Request-Method": method, "Access-Control-Request-Headers": "content-type" });
    if (origin !== null) {
      headers.set("Origin", origin);
    }
    return new Request(URL_REPORT, { method: "OPTIONS", headers });
  }

  it("allows the site origin", async () => {
    const res = await send(preflight(ORIGIN));
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
    expect(res.headers.get("access-control-allow-methods")).toBe("POST");
    expect(res.headers.get("access-control-allow-headers")).toBe("Content-Type");
    expect(res.headers.get("vary")).toBe("Origin");
  });

  it.each([["https://evil.example"], ["https://beta.moyuri-kudo.com"], ["null"], [null]])(
    "refuses origin %s",
    async (origin) => {
      const res = await send(preflight(origin));
      expect(res.status).toBe(403);
      expect(res.headers.get("access-control-allow-origin")).toBeNull();
    },
  );

  it("refuses a preflight for another method", async () => {
    const res = await send(preflight(ORIGIN, "PUT"));
    expect(res.status).toBe(403);
  });

  it("sets the allow-origin header on POST only for the site origin", async () => {
    const body = JSON.stringify([violation("https://cdn.example.com/a.js")]);
    const own = await send(reportRequest(body));
    expect(own.headers.get("access-control-allow-origin")).toBe(ORIGIN);
    const other = await send(reportRequest(body, "application/reports+json", { Origin: "https://evil.example" }));
    expect(other.status).toBe(204);
    expect(other.headers.get("access-control-allow-origin")).toBeNull();
  });
});

describe("input handling", () => {
  it.each(["application/json", "text/plain", "multipart/form-data"])("415 for %s", async (type) => {
    const res = await send(reportRequest(JSON.stringify([violation("inline")]), type));
    expect(res.status).toBe(415);
    expect(await rows()).toEqual([]);
  });

  it.each(["{", "[1,", "\u0000", "null", '{"type":"csp-violation"}'])("400 for malformed body %j", async (body) => {
    const res = await send(reportRequest(body));
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("");
  });

  it("400 for invalid UTF-8", async () => {
    const res = await send(reportRequest(new Uint8Array([0x5b, 0xff, 0x5d])));
    expect(res.status).toBe(400);
  });

  it("413 when the streamed body exceeds the cap without Content-Length", async () => {
    const chunk = new Uint8Array(16 * 1024).fill(0x20);
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent > MAX_BODY_BYTES) {
          controller.close();
          return;
        }
        sent += chunk.byteLength;
        controller.enqueue(chunk);
      },
    });
    const request = new Request(URL_REPORT, {
      method: "POST",
      headers: { "Content-Type": "application/reports+json" },
      body: stream,
      duplex: "half",
    } as RequestInit);
    expect(request.headers.get("content-length")).toBeNull();
    const res = await send(request);
    expect(res.status).toBe(413);
  });

  it("413 when Content-Length is over the cap", async () => {
    const body = " ".repeat(MAX_BODY_BYTES + 1);
    const res = await send(reportRequest(body));
    expect(res.status).toBe(413);
  });

  it("does not echo input and logs counts only", async () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const marker = "https://secret-marker.example/x";
    const res = await send(reportRequest(JSON.stringify([violation(marker)])));
    expect(res.status).toBe(204);
    expect(await res.text()).toBe("");
    const logged = spy.mock.calls.map((call) => String(call[0])).join("\n");
    expect(logged).not.toContain("secret-marker");
    expect(logged).not.toContain("/works/a");
    expect(logged).toContain('"outcome":"accepted"');
  });
});

describe("storage", () => {
  it("stores a Reporting API report normalised", async () => {
    const res = await send(reportRequest(JSON.stringify([violation("https://cdn.example.com/a.js?q=1")])));
    expect(res.status).toBe(204);
    expect(await rows()).toEqual([
      {
        directive: "script-src-elem",
        blocked_origin: "https://cdn.example.com",
        document_path: "/works/a",
        count: 1,
        first_seen: NOW,
        last_seen: NOW,
      },
    ]);
  });

  it("stores a legacy csp-report", async () => {
    const body = JSON.stringify({
      "csp-report": {
        "document-uri": `${ORIGIN}/about?ref=x`,
        "blocked-uri": "eval",
        "violated-directive": "script-src 'self'",
      },
    });
    const res = await send(reportRequest(body, "application/csp-report"));
    expect(res.status).toBe(204);
    expect(await rows()).toMatchObject([{ directive: "script-src", blocked_origin: "eval", document_path: "/about" }]);
  });

  it("UPSERTs repeated reports: count grows, first_seen stays, last_seen moves", async () => {
    const body = JSON.stringify([violation("inline"), violation("inline")]);
    await send(reportRequest(body));
    vi.setSystemTime(NOW + 60_000);
    await send(reportRequest(JSON.stringify([violation("inline")])));
    expect(await rows()).toMatchObject([{ blocked_origin: "inline", count: 3, first_seen: NOW, last_seen: NOW + 60_000 }]);
  });

  it("ignores extension and foreign-document reports with 204 and stores nothing", async () => {
    const body = JSON.stringify([
      violation("chrome-extension://abc/x.js"),
      violation("moz-extension://abc/x.js"),
      violation("https://cdn.example.com/a.js", "https://other.example/page"),
      violation("https://cdn.example.com/a.js", "https://beta.moyuri-kudo.com/page"),
    ]);
    const res = await send(reportRequest(body));
    expect(res.status).toBe(204);
    expect(await rows()).toEqual([]);
  });

  it("stores SQL-looking values literally", async () => {
    const injection = "'); DROP TABLE violations; --";
    const body = JSON.stringify([violation(injection, `${ORIGIN}/a'%20OR%201=1--`, "img-src'; DELETE FROM overflow;")]);
    await send(reportRequest(body));
    expect(await rows()).toMatchObject([
      { directive: "img-src';", blocked_origin: injection, document_path: "/a'%20OR%201=1--", count: 1 },
    ]);
  });

  it(`keeps at most ${MAX_KEYS_PER_REQUEST} distinct keys per request and counts the rest as overflow`, async () => {
    const reports = Array.from({ length: MAX_KEYS_PER_REQUEST + 5 }, (_, i) => violation(`https://h${i}.example.com/`));
    reports.push(violation("https://h0.example.com/"), violation(`https://h${MAX_KEYS_PER_REQUEST}.example.com/`));
    const res = await send(reportRequest(JSON.stringify(reports)));
    expect(res.status).toBe(204);
    const all = await rows();
    expect(all).toHaveLength(MAX_KEYS_PER_REQUEST);
    expect(all.find((r) => r.blocked_origin === "https://h0.example.com")?.count).toBe(2);
    expect(await overflowCount()).toBe(6);
  });
});

describe("daily new-row cap", () => {
  async function fill(count: number, firstSeen: number): Promise<void> {
    const statements = Array.from({ length: count }, (_, i) =>
      env.DB.prepare(
        "INSERT INTO violations (directive, blocked_origin, document_path, count, first_seen, last_seen) VALUES ('img-src', ?1, '/', 1, ?2, ?2)",
      ).bind(`https://fill${i}.example.com`, firstSeen),
    );
    await env.DB.batch(statements);
  }

  it("counts new rows over the cap as overflow but keeps updating existing rows", async () => {
    await fill(DAILY_NEW_ROW_CAP, NOW - 1000);
    const body = JSON.stringify([
      violation("https://new1.example.com/"),
      violation("https://new2.example.com/"),
      violation("https://new2.example.com/"),
      violation("https://fill0.example.com/", `${ORIGIN}/`, "img-src"),
    ]);
    const res = await send(reportRequest(body));
    expect(res.status).toBe(204);
    const all = await rows();
    expect(all).toHaveLength(DAILY_NEW_ROW_CAP);
    expect(all.find((r) => r.blocked_origin === "https://fill0.example.com")?.count).toBe(2);
    expect(await overflowCount()).toBe(3);

    await send(reportRequest(JSON.stringify([violation("https://new3.example.com/")])));
    expect(await overflowCount()).toBe(4);
  });

  it("does not count rows first seen on earlier days", async () => {
    await fill(DAILY_NEW_ROW_CAP, NOW - DAY_MS);
    await send(reportRequest(JSON.stringify([violation("https://new1.example.com/")])));
    expect(await rows()).toHaveLength(DAILY_NEW_ROW_CAP + 1);
    expect(await overflowCount()).toBe(0);
  });
});

describe("scheduled cleanup", () => {
  it("deletes rows last seen more than 30 days ago and old overflow days", async () => {
    const keep = NOW - 29 * DAY_MS;
    const drop = NOW - 31 * DAY_MS;
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO violations (directive, blocked_origin, document_path, count, first_seen, last_seen) VALUES ('a', 'x', '/', 1, ?1, ?1), ('b', 'x', '/', 1, ?2, ?3)",
      ).bind(drop, drop, keep),
      env.DB.prepare("INSERT INTO violations (directive, blocked_origin, document_path, count, first_seen, last_seen) VALUES ('c', 'x', '/', 1, ?1, ?1)").bind(drop),
      env.DB.prepare("INSERT INTO overflow (day, count) VALUES ('2026-10-01', 5), ('2026-11-20', 2)"),
    ]);
    const ctx = createExecutionContext();
    await worker.scheduled(createScheduledController({ scheduledTime: NOW, cron: "0 18 * * *" }), env);
    await waitOnExecutionContext(ctx);
    expect((await rows()).map((r) => r.directive)).toEqual(["b"]);
    const { results } = await env.DB.prepare("SELECT day FROM overflow").all<{ day: string }>();
    expect(results.map((r) => r.day)).toEqual(["2026-11-20"]);
  });
});
