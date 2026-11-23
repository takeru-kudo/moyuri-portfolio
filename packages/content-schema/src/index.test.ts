import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  categoriesFileSchema,
  profileFileSchema,
  projectSchema,
  projectsFileSchema,
  siteFileSchema,
} from "./index.ts";

const TS = "2026-01-01T00:00:00.000Z";
const published = { createdAt: TS, updatedAt: TS, publishedAt: TS, revisedAt: TS };

const category = { id: "cat1", ...published, name: "Illustration", slug: "illustration" };

function project(overrides: Record<string, unknown> = {}) {
  return {
    id: "p1",
    ...published,
    title: "Work",
    slug: "work-1",
    cover: { url: "https://images.microcms-assets.io/assets/x/y/a.png", width: 1200, height: 630 },
    summary: "Summary",
    body: "<p>Body</p>",
    category,
    order: 1,
    featured: true,
    ...overrides,
  };
}

describe("projectsFileSchema", () => {
  it("parses a full list", () => {
    const parsed = projectsFileSchema.parse({ contents: [project()], totalCount: 1 });
    assert.equal(parsed.contents[0]?.category?.slug, "illustration");
    assert.equal(parsed.contents[0]?.featured, true);
  });

  it("accepts empty optional fields in the forms microCMS returns", () => {
    const minimal = {
      id: "p2",
      createdAt: TS,
      updatedAt: TS,
      title: "Draft",
      slug: "draft",
      cover: { url: "https://images.microcms-assets.io/a.svg" },
    };
    const parsed = projectSchema.parse(minimal);
    assert.equal(parsed.featured, false);
    assert.equal(parsed.publishedAt, undefined);
    const nulls = projectSchema.parse({ ...minimal, summary: null, body: null, category: null, order: null });
    assert.equal(nulls.category, null);
    assert.equal(projectSchema.parse({ ...minimal, summary: "", body: "" }).summary, "");
  });

  it("strips unknown fields", () => {
    const parsed = projectSchema.parse(project({ extra: 1 }));
    assert.ok(!("extra" in parsed));
  });

  it("rejects invalid items", () => {
    const bad: Array<Record<string, unknown>> = [
      { slug: "Bad_Slug" },
      { slug: "a--b" },
      { slug: "" },
      { title: "" },
      { title: "x".repeat(101) },
      { summary: "x".repeat(301) },
      { order: -1 },
      { order: 10000 },
      { order: 1.5 },
      { cover: undefined },
      { cover: { url: "http://insecure.example/a.png" } },
      { cover: { url: "javascript:alert(1)" } },
      { category: { id: "c", ...published, name: "", slug: "c" } },
      { id: "" },
      { createdAt: "yesterday" },
      { featured: "yes" },
    ];
    for (const overrides of bad) {
      const result = projectSchema.safeParse(project(overrides));
      assert.equal(result.success, false, JSON.stringify(overrides));
    }
  });

  it("rejects totalCount mismatch and duplicate ids or slugs", () => {
    assert.equal(projectsFileSchema.safeParse({ contents: [project()], totalCount: 2 }).success, false);
    const dupId = projectsFileSchema.safeParse({
      contents: [project(), project({ slug: "other" })],
      totalCount: 2,
    });
    assert.equal(dupId.success, false);
    const dupSlug = projectsFileSchema.safeParse({
      contents: [project(), project({ id: "p9" })],
      totalCount: 2,
    });
    assert.equal(dupSlug.success, false);
    assert.deepEqual(dupSlug.error?.issues.map((i) => i.path), [["contents", 1, "slug"]]);
  });

  it("does not include input values in error messages", () => {
    const secret = "SECRET_DRAFT_TITLE";
    const result = projectsFileSchema.safeParse({
      contents: [project({ slug: secret, title: secret.repeat(10) })],
      totalCount: 1,
    });
    assert.equal(result.success, false);
    assert.ok(!JSON.stringify(result.error?.issues).includes(secret));
  });
});

describe("categoriesFileSchema", () => {
  it("parses and validates", () => {
    assert.equal(categoriesFileSchema.parse({ contents: [category], totalCount: 1 }).totalCount, 1);
    assert.equal(categoriesFileSchema.parse({ contents: [], totalCount: 0 }).contents.length, 0);
    assert.equal(
      categoriesFileSchema.safeParse({ contents: [{ ...category, name: "x".repeat(51) }], totalCount: 1 })
        .success,
      false,
    );
    assert.equal(categoriesFileSchema.safeParse({ items: [], totalCount: 0 }).success, false);
  });
});

describe("object APIs", () => {
  it("parses profile and site", () => {
    assert.equal(profileFileSchema.parse({ ...published, name: "Moyuri", bio: "Hello" }).name, "Moyuri");
    assert.equal(profileFileSchema.parse({ ...published }).bio, undefined);
    assert.equal(siteFileSchema.parse({ ...published, tagline: "" }).tagline, "");
  });

  it("enforces length limits", () => {
    assert.equal(profileFileSchema.safeParse({ ...published, bio: "x".repeat(2001) }).success, false);
    assert.equal(profileFileSchema.safeParse({ ...published, name: "x".repeat(51) }).success, false);
    assert.equal(siteFileSchema.safeParse({ ...published, tagline: "x".repeat(101) }).success, false);
    assert.equal(siteFileSchema.safeParse({ tagline: "x" }).success, false);
  });
});
