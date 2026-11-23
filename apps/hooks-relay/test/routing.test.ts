import { describe, expect, it } from "vitest";
import { classify, route } from "../src/routing.ts";

function decide(payload: unknown) {
  return route(classify(payload));
}

function body(oldStatus: string[] | null, newStatus: string[] | null, extra: Record<string, unknown> = {}) {
  return {
    api: "projects",
    id: "abc123",
    contents: {
      old: oldStatus === null ? null : { id: "abc123", status: oldStatus },
      new: newStatus === null ? null : { id: "abc123", status: newStatus },
    },
    ...extra,
  };
}

describe("routing table", () => {
  it.each([
    ["create as draft", null, ["DRAFT"], "beta", "projects-draft"],
    ["create and publish", null, ["PUBLISH"], "prod", "projects-abc123-publish"],
    ["update a draft", ["DRAFT"], ["DRAFT"], "beta", "projects-draft"],
    ["publish a draft", ["DRAFT"], ["PUBLISH"], "prod", "projects-abc123-publish"],
    ["update published content", ["PUBLISH"], ["PUBLISH"], "prod", "projects-abc123-publish"],
    ["draft on published content", ["PUBLISH"], ["PUBLISH", "DRAFT"], "prod", "projects-abc123-publish"],
    ["unpublish", ["PUBLISH"], ["CLOSED"], "prod", "projects-abc123-publish"],
    ["update closed content", ["CLOSED"], ["DRAFT"], "beta", "projects-draft"],
    ["delete published", ["PUBLISH"], null, "prod", "projects-abc123-publish"],
    ["delete draft", ["DRAFT"], null, "beta", "projects-draft"],
  ] as const)("%s", (_name, oldStatus, newStatus, target, reason) => {
    const result = decide(body(oldStatus ? [...oldStatus] : null, newStatus ? [...newStatus] : null));
    expect(result).toMatchObject({ ok: true, target, reason });
  });

  it.each([
    ["not an object", "hello"],
    ["array", []],
    ["missing contents", { api: "projects", id: "abc123" }],
    ["both null", body(null, null)],
    ["status not an array", { api: "projects", id: "abc123", contents: { old: null, new: { status: "PUBLISH" } } }],
    ["unknown status value", body(null, ["SCHEDULED"])],
    ["empty status", body(null, [])],
    ["missing old key", { api: "projects", id: "abc123", contents: { new: { status: ["DRAFT"] } } }],
  ])("unknown shape (%s) goes to prod", (_name, payload) => {
    const result = decide(payload);
    expect(result.ok).toBe(true);
    expect(result).toMatchObject({ target: "prod", decision: "unknown" });
  });

  it("unknown shape keeps api and id in the reason when present", () => {
    expect(decide(body(null, null))).toMatchObject({ reason: "projects-abc123-unknown" });
    expect(decide(undefined)).toMatchObject({ ok: true, reason: "unknown" });
  });
});

describe("reason", () => {
  it("never includes the content ID for draft-only changes", () => {
    const result = decide(body(["DRAFT"], ["DRAFT"], { id: "secret-draft-id" }));
    expect(result).toMatchObject({ ok: true, target: "beta" });
    expect(result.ok && result.reason).not.toContain("secret-draft-id");
  });

  it("ignores an invalid content ID for draft-only changes", () => {
    expect(decide(body(["DRAFT"], ["DRAFT"], { id: "bad id!" }))).toMatchObject({ ok: true, reason: "projects-draft" });
  });

  it.each([
    ["api with a space", { api: "my api" }],
    ["api with a newline", { api: "projects\n" }],
    ["non-ascii api", { api: "作品" }],
    ["empty api", { api: "" }],
  ])("rejects a draft-only change with %s", (_name, extra) => {
    expect(decide(body(null, ["DRAFT"], extra)).ok).toBe(false);
  });

  it("accepts a draft reason of exactly 64 characters and rejects 65", () => {
    const api64 = "a".repeat(64 - "-draft".length);
    expect(decide(body(null, ["DRAFT"], { api: api64 }))).toMatchObject({ ok: true, reason: `${api64}-draft` });
    expect(decide(body(null, ["DRAFT"], { api: `${api64}a` })).ok).toBe(false);
  });

  it("only uses [A-Za-z0-9_-]", () => {
    const result = decide(body(null, ["PUBLISH"], { api: "Pro_jects-1", id: "ID_9-x" }));
    expect(result).toMatchObject({ ok: true, reason: "Pro_jects-1-ID_9-x-publish", fallback: "none" });
  });
});

describe("prod reason fallback", () => {
  it.each([
    ["id with a slash", { id: "a/b" }, ["PUBLISH"], "projects-publish", "without_id"],
    ["id with a space", { id: "a b" }, ["PUBLISH"], "projects-publish", "without_id"],
    ["api with a space", { api: "my api" }, ["PUBLISH"], "publish", "decision_only"],
    ["non-ascii api and id", { api: "作品", id: "作品1" }, ["PUBLISH"], "publish", "decision_only"],
    ["empty api", { api: "" }, ["PUBLISH"], "publish", "decision_only"],
    ["unknown shape with a bad id", { id: "a/b" }, ["SCHEDULED"], "projects-unknown", "without_id"],
  ])("%s", (_name, extra, newStatus, reason, fallback) => {
    expect(decide(body(null, newStatus, extra))).toMatchObject({ ok: true, target: "prod", reason, fallback });
  });

  it("uses the full reason at exactly 64 characters", () => {
    const id = "b".repeat(64 - "projects--publish".length);
    expect(decide(body(null, ["PUBLISH"], { id }))).toMatchObject({
      ok: true,
      reason: `projects-${id}-publish`,
      fallback: "none",
    });
  });

  it("drops the content ID when the full reason exceeds 64 characters", () => {
    const result = decide(body(null, ["PUBLISH"], { api: "a".repeat(30), id: "b".repeat(30) }));
    expect(result).toMatchObject({ ok: true, target: "prod", reason: `${"a".repeat(30)}-publish`, fallback: "without_id" });
  });

  it("falls back to the decision alone when the API name is too long", () => {
    const result = decide(body(["PUBLISH"], null, { api: "a".repeat(64) }));
    expect(result).toMatchObject({ ok: true, target: "prod", reason: "publish", fallback: "decision_only" });
  });

  it("never fails for prod", () => {
    for (const extra of [{ api: "x".repeat(200), id: "y".repeat(200) }, { api: "!", id: "?" }, { api: 1, id: [] }]) {
      expect(decide(body(null, ["PUBLISH"], extra)).ok).toBe(true);
      expect(decide(body(null, ["SCHEDULED"], extra)).ok).toBe(true);
    }
  });
});
