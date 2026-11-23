import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { ContentError, loadContent, resolveSource, sortProjects } from "./content.ts";

const FIXTURE_DIR = fileURLToPath(new URL("../../fixtures/content/", import.meta.url));
const TS = "2026-01-01T00:00:00.000Z";
const SECRET = "TITLE_SENTINEL_dddd";

function sys(id: string) {
  return { id, createdAt: TS, updatedAt: TS };
}

function project(n: number, extra: Record<string, unknown> = {}) {
  return {
    ...sys(`p${n}`),
    title: `${SECRET}-${n}`,
    slug: `p${n}`,
    cover: { url: "https://images.microcms-assets.io/a.png" },
    ...extra,
  };
}

function list(contents: unknown[]) {
  return { contents, totalCount: contents.length };
}

let workDir: string;
let counter = 0;
before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), "site-content-test-"));
});
after(async () => {
  await rm(workDir, { recursive: true, force: true });
});

async function writeDir(files: Record<string, unknown>): Promise<string> {
  counter += 1;
  const dir = path.join(workDir, `c${counter}`);
  await mkdir(dir);
  const all = { categories: list([]), projects: list([]), profile: null, site: null, ...files };
  for (const [name, value] of Object.entries(all)) {
    await writeFile(path.join(dir, `${name}.json`), JSON.stringify(value));
  }
  return dir;
}

async function rejection(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (err) {
    return err as Error;
  }
  assert.fail("expected rejection");
}

describe("resolveSource", () => {
  it("uses the fixture directory and published mode by default", () => {
    assert.deepEqual(resolveSource({}, "/fx"), { dir: "/fx", mode: "published", fixture: true });
  });
  it("uses CONTENT_DIR and CONTENT_MODE", () => {
    assert.deepEqual(resolveSource({ CONTENT_DIR: "/c", CONTENT_MODE: "draft" }, "/fx"), {
      dir: "/c",
      mode: "draft",
      fixture: false,
    });
  });
  it("rejects a relative CONTENT_DIR and an unknown mode", () => {
    assert.throws(() => resolveSource({ CONTENT_DIR: "rel" }, "/fx"), ContentError);
    assert.throws(() => resolveSource({ CONTENT_MODE: "all" }, "/fx"), ContentError);
  });
  it("requires CONTENT_DIR when CONTENT_MODE is set", () => {
    for (const mode of ["published", "draft"]) {
      assert.throws(
        () => resolveSource({ CONTENT_MODE: mode }, "/fx"),
        /^ContentError: CONTENT_DIR is required when CONTENT_MODE is set$/,
      );
      assert.throws(() => resolveSource({ CONTENT_MODE: mode, CONTENT_DIR: "" }, "/fx"), ContentError);
    }
  });
});

describe("loadContent", () => {
  it("loads the committed fixtures in published mode", async () => {
    const { content, dropped } = await loadContent(FIXTURE_DIR, "published");
    assert.equal(dropped, 0);
    assert.deepEqual(
      content.projects.map((p) => p.slug),
      ["sample-1", "sample-2"],
    );
    assert.ok(content.site?.tagline);
  });

  it("builds with no content at all", async () => {
    const dir = await writeDir({});
    for (const mode of ["published", "draft"] as const) {
      const { content, dropped } = await loadContent(dir, mode);
      assert.deepEqual(content, { categories: [], projects: [], profile: null, site: null });
      assert.equal(dropped, 0);
    }
  });

  it("fails in published mode on an invalid item without echoing values", async () => {
    const bad = project(2, { slug: `BAD ${SECRET}` });
    const dir = await writeDir({ projects: list([project(1), bad]) });
    const err = await rejection(loadContent(dir, "published"));
    assert.ok(err instanceof ContentError);
    assert.match(err.message, /^projects\.json: 1 issue\(s\) at contents\.1\.slug$/);
    assert.ok(!err.message.includes(SECRET));
  });

  it("fails in published mode on a duplicate slug or an invalid object", async () => {
    const dup = await writeDir({ projects: list([project(1), project(2, { slug: "p1" })]) });
    assert.ok((await rejection(loadContent(dup, "published"))) instanceof ContentError);
    const badSite = await writeDir({ site: { ...sys("x"), tagline: 1 } });
    assert.match((await rejection(loadContent(badSite, "published"))).message, /^site\.json: /);
  });

  it("drops invalid and duplicate items in draft mode and counts them", async () => {
    const dir = await writeDir({
      projects: list([
        project(1),
        project(2, { slug: "p1" }),
        project(3, { cover: { url: "http://insecure" } }),
        project(1, { slug: "p9" }),
        project(4),
      ]),
      site: { createdAt: "not a date" },
    });
    const { content, dropped } = await loadContent(dir, "draft");
    assert.deepEqual(
      content.projects.map((p) => p.id),
      ["p1", "p4"],
    );
    assert.equal(content.site, null);
    assert.equal(dropped, 4);
  });

  it("fails in draft mode when a list file has the wrong shape", async () => {
    const dir = await writeDir({ projects: { contents: [project(1)], totalCount: 2 } });
    assert.equal((await rejection(loadContent(dir, "draft"))).message, "projects.json: is not a list file");
  });

  it("fails on a missing or malformed file with a fixed message", async () => {
    const dir = await writeDir({});
    await writeFile(path.join(dir, "site.json"), `{${SECRET}`);
    assert.equal((await rejection(loadContent(dir, "draft"))).message, "site.json: is not valid JSON");
    assert.equal(
      (await rejection(loadContent(path.join(dir, "missing"), "draft"))).message,
      "categories.json: cannot be read",
    );
  });
});

describe("sortProjects", () => {
  it("orders by order (missing last), then title, then id", async () => {
    const { content } = await loadContent(FIXTURE_DIR, "published");
    const base = content.projects[0]!;
    const mk = (id: string, title: string, order: number | null) => ({ ...base, id, title, order });
    const sorted = sortProjects([mk("a", "B", null), mk("b", "A", null), mk("c", "Z", 2), mk("d", "Y", 1), mk("e", "A", null)]);
    assert.deepEqual(
      sorted.map((p) => p.id),
      ["d", "c", "b", "e", "a"],
    );
  });

  it("fixtures are valid JSON files", async () => {
    for (const name of ["categories", "projects", "profile", "site"]) {
      JSON.parse(await readFile(path.join(FIXTURE_DIR, `${name}.json`), "utf8"));
    }
  });
});
