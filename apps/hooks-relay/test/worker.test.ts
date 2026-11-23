import { env as testEnv, exports } from "cloudflare:workers";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { MAX_BODY_BYTES } from "../src/body.ts";
import { createAppJwt, USER_AGENT } from "../src/github.ts";
import worker from "../src/index.ts";
import {
  base64UrlToBytes,
  decodeJwtPart,
  generateTestKey,
  makeEnv,
  sign,
  signedRequest,
  type TestKey,
  webhookBody,
} from "./helpers.ts";

let key: TestKey;

beforeAll(async () => {
  key = await generateTestKey();
});

afterEach(() => {
  vi.restoreAllMocks();
});

interface Call {
  url: string;
  init: RequestInit;
}

function mockGitHub(tokenStatus = 201, dispatchStatus = 204): Call[] {
  const calls: Call[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    calls.push({ url, init: init ?? {} });
    if (url.endsWith("/access_tokens")) {
      return new Response(JSON.stringify({ token: "ghs_testtoken" }), { status: tokenStatus });
    }
    return new Response(null, { status: dispatchStatus });
  });
  return calls;
}

function headerOf(call: Call, name: string): string | null {
  return new Headers(call.init.headers).get(name);
}

async function send(request: Request, overrides = {}) {
  return worker.fetch(request, makeEnv(key.pem, overrides));
}

describe("paths and methods", () => {
  it("GET /healthz returns the version ID", async () => {
    const res = await send(new Request("https://hooks.moyuri-kudo.com/healthz"));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok", version: "11111111-2222-3333-4444-555555555555" });
  });

  it("serves /healthz through the configured version_metadata binding", async () => {
    const res = await exports.default.fetch("https://hooks.moyuri-kudo.com/healthz");
    expect(res.status).toBe(200);
    const data = (await res.json()) as { version: unknown };
    expect(data.version).toBe((testEnv as { CF_VERSION_METADATA: { id: string } }).CF_VERSION_METADATA.id);
  });

  it.each(["/", "/microcms/", "/healthz/x", "/MICROCMS", "/favicon.ico"])("404 for %s", async (path) => {
    const res = await send(new Request(`https://hooks.moyuri-kudo.com${path}`, { method: "POST" }));
    expect(res.status).toBe(404);
  });

  it.each([
    ["GET", "/microcms", "POST"],
    ["PUT", "/microcms", "POST"],
    ["POST", "/healthz", "GET"],
    ["HEAD", "/healthz", "GET"],
  ])("405 for %s %s", async (method, path, allow) => {
    const res = await send(new Request(`https://hooks.moyuri-kudo.com${path}`, { method }));
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe(allow);
  });
});

describe("signature", () => {
  const payload = webhookBody("projects", "abc123", ["DRAFT"], ["PUBLISH"]);

  it("accepts a valid signature (upper-case hex too)", async () => {
    mockGitHub();
    expect((await send(await signedRequest(payload))).status).toBe(202);
    const upper = (await sign(payload)).toUpperCase();
    expect((await send(await signedRequest(payload, upper))).status).toBe(202);
  });

  it.each([
    ["missing", null],
    ["empty", ""],
    ["wrong", "0".repeat(64)],
    ["short", "abcd"],
    ["non-hex", "z".repeat(64)],
  ])("401 for a %s signature, without calling GitHub", async (_name, signature) => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const res = await send(await signedRequest(payload, signature));
    expect(res.status).toBe(401);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("401 for a signature made with another secret", async () => {
    const res = await send(await signedRequest(payload, await sign(payload, "other")));
    expect(res.status).toBe(401);
  });

  it("401 when the body differs from the signed one", async () => {
    const res = await send(await signedRequest(`${payload} `, await sign(payload)));
    expect(res.status).toBe(401);
  });

  it("401 when the secret is not configured", async () => {
    const res = await send(await signedRequest(payload), { MICROCMS_WEBHOOK_SECRET: "" });
    expect(res.status).toBe(401);
  });

  it("verifies before parsing JSON", async () => {
    const res = await send(await signedRequest("not json", "0".repeat(64)));
    expect(res.status).toBe(401);
  });
});

describe("body limit", () => {
  it("413 from Content-Length alone", async () => {
    const req = new Request("https://hooks.moyuri-kudo.com/microcms", {
      method: "POST",
      headers: { "content-length": String(MAX_BODY_BYTES + 1) },
      body: "{}",
    });
    expect((await send(req)).status).toBe(413);
  });

  it("413 for a streamed body without Content-Length", async () => {
    const chunk = new Uint8Array(256 * 1024);
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
    const req = new Request("https://hooks.moyuri-kudo.com/microcms", { method: "POST", body: stream });
    expect(req.headers.get("content-length")).toBeNull();
    expect((await send(req)).status).toBe(413);
  });

  it("413 when Content-Length understates the body", async () => {
    const big = "x".repeat(MAX_BODY_BYTES + 1);
    const req = new Request("https://hooks.moyuri-kudo.com/microcms", {
      method: "POST",
      headers: { "content-length": "2", "x-microcms-signature": await sign(big) },
      body: big,
    });
    expect((await send(req)).status).toBe(413);
  });

  it("400 for a non-numeric Content-Length, without calling GitHub", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const req = new Request("https://hooks.moyuri-kudo.com/microcms", {
      method: "POST",
      headers: { "content-length": "12abc" },
      body: "{}",
    });
    expect(req.headers.get("content-length")).toBe("12abc");
    expect((await send(req)).status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("accepts exactly the limit", async () => {
    const exact = "x".repeat(MAX_BODY_BYTES);
    mockGitHub();
    const res = await send(await signedRequest(exact));
    expect(res.status).toBe(202);
  });
});

describe("dispatch", () => {
  it("dispatches prod with the content ID for a publish", async () => {
    const calls = mockGitHub();
    const res = await send(await signedRequest(webhookBody("projects", "abc123", ["DRAFT"], ["PUBLISH"])));
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ target: "prod" });
    expect(calls).toHaveLength(2);
    const dispatch = calls[1];
    expect(dispatch.url).toBe(
      "https://api.github.com/repos/takeru-kudo/moyuri-portfolio/actions/workflows/deploy.yml/dispatches",
    );
    expect(dispatch.init.method).toBe("POST");
    expect(headerOf(dispatch, "authorization")).toBe("Bearer ghs_testtoken");
    expect(headerOf(dispatch, "user-agent")).toBe(USER_AGENT);
    expect(JSON.parse(String(dispatch.init.body))).toEqual({
      ref: "main",
      inputs: { target: "prod", reason: "projects-abc123-publish" },
    });
  });

  it("dispatches beta without the content ID for a draft-only change", async () => {
    const calls = mockGitHub();
    const res = await send(await signedRequest(webhookBody("projects", "draft-only-id", ["DRAFT"], ["DRAFT"])));
    expect(res.status).toBe(202);
    const body = String(calls[1].init.body);
    expect(JSON.parse(body)).toEqual({ ref: "main", inputs: { target: "beta", reason: "projects-draft" } });
    expect(body).not.toContain("draft-only-id");
  });

  it("dispatches prod for a signed non-JSON body", async () => {
    const calls = mockGitHub();
    const res = await send(await signedRequest("not json"));
    expect(res.status).toBe(202);
    expect(JSON.parse(String(calls[1].init.body))).toEqual({ ref: "main", inputs: { target: "prod", reason: "unknown" } });
  });

  it("422 and no GitHub call when a draft-only reason would contain other characters", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const logSpy = vi.spyOn(console, "log");
    const res = await send(await signedRequest(webhookBody("my api", "abc123", ["DRAFT"], ["DRAFT"])));
    expect(res.status).toBe(422);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(logSpy.mock.calls.map((c) => String(c[0])).join("\n")).toContain('"outcome":"invalid_reason"');
  });

  it("dispatches prod with a shorter reason when the content ID is invalid, and logs the fallback", async () => {
    const calls = mockGitHub();
    const logSpy = vi.spyOn(console, "log");
    const res = await send(await signedRequest(webhookBody("projects", "a b", null, ["PUBLISH"])));
    expect(res.status).toBe(202);
    expect(JSON.parse(String(calls[1].init.body))).toEqual({
      ref: "main",
      inputs: { target: "prod", reason: "projects-publish" },
    });
    const logged = logSpy.mock.calls.map((c) => String(c[0])).join("\n");
    expect(logged).toContain('"fallback":"without_id"');
    expect(logged).toContain('"id":"(invalid)"');
    expect(logged).not.toContain("a b");
  });

  it("dispatches prod with the decision alone when the API name is too long", async () => {
    const calls = mockGitHub();
    const res = await send(await signedRequest(webhookBody("a".repeat(70), "abc123", ["PUBLISH"], ["CLOSED"])));
    expect(res.status).toBe(202);
    expect(JSON.parse(String(calls[1].init.body)).inputs).toEqual({ target: "prod", reason: "publish" });
  });

  it("requests a token for actions: write on the one repository", async () => {
    const calls = mockGitHub();
    await send(await signedRequest(webhookBody("projects", "abc123", null, ["PUBLISH"])));
    const tokenCall = calls[0];
    expect(tokenCall.url).toBe("https://api.github.com/app/installations/67890/access_tokens");
    expect(tokenCall.init.method).toBe("POST");
    expect(headerOf(tokenCall, "user-agent")).toBe(USER_AGENT);
    expect(headerOf(tokenCall, "accept")).toBe("application/vnd.github+json");
    expect(JSON.parse(String(tokenCall.init.body))).toEqual({
      repositories: ["moyuri-portfolio"],
      permissions: { actions: "write" },
    });
    const jwt = headerOf(tokenCall, "authorization")?.replace(/^Bearer /, "") ?? "";
    expect(jwt.split(".")).toHaveLength(3);
  });

  it.each([
    ["token 401", 401, 204],
    ["token 500", 500, 204],
    ["dispatch 404", 201, 404],
    ["dispatch 422", 201, 422],
    ["dispatch redirect", 201, 302],
  ])("502 when GitHub fails (%s)", async (_name, tokenStatus, dispatchStatus) => {
    mockGitHub(tokenStatus, dispatchStatus);
    const res = await send(await signedRequest(webhookBody("projects", "abc123", null, ["PUBLISH"])));
    expect(res.status).toBe(502);
  });

  it("502 when fetch throws", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("network"));
    const res = await send(await signedRequest(webhookBody("projects", "abc123", null, ["PUBLISH"])));
    expect(res.status).toBe(502);
  });

  it("502 when the token response has no token", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 201 }));
    const res = await send(await signedRequest(webhookBody("projects", "abc123", null, ["PUBLISH"])));
    expect(res.status).toBe(502);
  });

  it("502 for a non-PKCS#8 private key", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n";
    const res = await send(await signedRequest(webhookBody("projects", "abc123", null, ["PUBLISH"])), {
      GITHUB_APP_PRIVATE_KEY: pkcs1,
    });
    expect(res.status).toBe(502);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("500 and no GitHub call for invalid App settings", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const res = await send(await signedRequest(webhookBody("projects", "abc123", null, ["PUBLISH"])), {
      GITHUB_APP_ID: "0",
    });
    expect(res.status).toBe(500);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("never logs the body, signature, token or key", async () => {
    mockGitHub();
    const logSpy = vi.spyOn(console, "log");
    const errorSpy = vi.spyOn(console, "error");
    const payload = JSON.stringify({
      ...JSON.parse(webhookBody("projects", "abc123", null, ["PUBLISH"])),
      title: "SensitiveTitle",
    });
    const signature = await sign(payload);
    await send(await signedRequest(payload, signature));
    const logged = [...logSpy.mock.calls, ...errorSpy.mock.calls].map((c) => c.map(String).join(" ")).join("\n");
    expect(logged).toContain('"outcome":"dispatched"');
    for (const secret of ["SensitiveTitle", signature, "ghs_testtoken", "PRIVATE KEY", "test-webhook-secret"]) {
      expect(logged).not.toContain(secret);
    }
  });
});

describe("JWT", () => {
  it("has iat 60 s back, exp within 10 min of iat, iss = App ID, and a valid RS256 signature", async () => {
    const now = 1_800_000_000;
    const jwt = await createAppJwt("12345", key.pem, now);
    const [header, payload, signature] = jwt.split(".");
    expect(decodeJwtPart(header)).toEqual({ alg: "RS256", typ: "JWT" });
    const claims = decodeJwtPart(payload) as { iat: number; exp: number; iss: string };
    expect(claims.iat).toBe(now - 60);
    expect(claims.exp).toBeGreaterThan(now);
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
    expect(claims.exp - now).toBeLessThanOrEqual(600);
    expect(claims.iss).toBe("12345");
    const valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key.publicKey,
      base64UrlToBytes(signature),
      new TextEncoder().encode(`${header}.${payload}`),
    );
    expect(valid).toBe(true);
  });
});
