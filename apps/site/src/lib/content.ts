// Reads and validates the content JSON files written by tools/fetch-content.
// published mode: any invalid file or item fails the build.
// draft mode: invalid or duplicate list items and invalid objects are dropped and counted.

import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  categoriesFileSchema,
  categorySchema,
  profileFileSchema,
  projectsFileSchema,
  projectSchema,
  siteFileSchema,
  type Category,
  type Profile,
  type Project,
  type Site,
} from "@portfolio/content-schema";

export type ContentMode = "published" | "draft";

export interface ContentSource {
  dir: string;
  mode: ContentMode;
  fixture: boolean;
}

export interface SiteContent {
  categories: Category[];
  projects: Project[];
  profile: Profile | null;
  site: Site | null;
}

export interface LoadResult {
  content: SiteContent;
  dropped: number;
}

interface Issue {
  readonly path: ReadonlyArray<PropertyKey>;
}

type ParseResult<T> =
  | { success: true; data: T }
  | { success: false; error: { readonly issues: ReadonlyArray<Issue> } };

interface Parser<T> {
  safeParse(input: unknown): ParseResult<T>;
}

const MAX_REPORTED_ISSUES = 5;

/** Error whose message contains file names, issue counts and schema paths only. */
export class ContentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContentError";
  }
}

/**
 * Resolves the content directory and mode from env. With neither CONTENT_DIR nor
 * CONTENT_MODE set, uses the fixture directory in published mode.
 */
export function resolveSource(env: Readonly<Record<string, string | undefined>>, fixtureDir: string): ContentSource {
  const dir = env.CONTENT_DIR ?? "";
  const modeSet = (env.CONTENT_MODE ?? "") !== "";
  const rawMode = modeSet ? env.CONTENT_MODE : "published";
  if (rawMode !== "published" && rawMode !== "draft") {
    throw new ContentError("CONTENT_MODE must be published or draft");
  }
  if (dir === "") {
    if (modeSet) throw new ContentError("CONTENT_DIR is required when CONTENT_MODE is set");
    return { dir: fixtureDir, mode: rawMode, fixture: true };
  }
  if (!path.isAbsolute(dir)) throw new ContentError("CONTENT_DIR must be an absolute path");
  return { dir, mode: rawMode, fixture: false };
}

function describeIssues(issues: ReadonlyArray<Issue>): string {
  const paths = issues
    .slice(0, MAX_REPORTED_ISSUES)
    .map((issue) => issue.path.map((part) => (typeof part === "symbol" ? "?" : String(part))).join(".") || "(root)");
  const more = issues.length > MAX_REPORTED_ISSUES ? ", ..." : "";
  return `${issues.length} issue(s) at ${paths.join(", ")}${more}`;
}

async function readJson(dir: string, name: string): Promise<unknown> {
  let text: string;
  try {
    text = await readFile(path.join(dir, name), "utf8");
  } catch {
    throw new ContentError(`${name}: cannot be read`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ContentError(`${name}: is not valid JSON`);
  }
}

function parseStrict<T>(name: string, parser: Parser<T>, raw: unknown): T {
  const result = parser.safeParse(raw);
  if (!result.success) throw new ContentError(`${name}: ${describeIssues(result.error.issues)}`);
  return result.data;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Keeps valid items with a first-seen id and slug; counts the rest. */
function parseListLenient<T extends { id: string; slug: string }>(
  name: string,
  item: Parser<T>,
  raw: unknown,
): { items: T[]; dropped: number } {
  if (!isRecord(raw) || !Array.isArray(raw.contents) || raw.totalCount !== raw.contents.length) {
    throw new ContentError(`${name}: is not a list file`);
  }
  const items: T[] = [];
  const ids = new Set<string>();
  const slugs = new Set<string>();
  let dropped = 0;
  for (const entry of raw.contents as unknown[]) {
    const result = item.safeParse(entry);
    if (!result.success || ids.has(result.data.id) || slugs.has(result.data.slug)) {
      dropped += 1;
      continue;
    }
    ids.add(result.data.id);
    slugs.add(result.data.slug);
    items.push(result.data);
  }
  return { items, dropped };
}

function parseObject<T>(name: string, parser: Parser<T>, raw: unknown, mode: ContentMode): { value: T | null; dropped: number } {
  if (raw === null) return { value: null, dropped: 0 };
  if (mode === "published") return { value: parseStrict(name, parser, raw), dropped: 0 };
  const result = parser.safeParse(raw);
  return result.success ? { value: result.data, dropped: 0 } : { value: null, dropped: 1 };
}

/** Orders projects by order (missing last), then title, then id. */
export function sortProjects(projects: ReadonlyArray<Project>): Project[] {
  const rank = (p: Project): number => p.order ?? Number.POSITIVE_INFINITY;
  return [...projects].sort(
    (a, b) => rank(a) - rank(b) || a.title.localeCompare(b.title, "ja") || a.id.localeCompare(b.id),
  );
}

/** Reads <dir>/{categories,projects,profile,site}.json and validates them for the mode. */
export async function loadContent(dir: string, mode: ContentMode): Promise<LoadResult> {
  const rawCategories = await readJson(dir, "categories.json");
  const rawProjects = await readJson(dir, "projects.json");
  const rawProfile = await readJson(dir, "profile.json");
  const rawSite = await readJson(dir, "site.json");
  let categories: Category[];
  let projects: Project[];
  let dropped = 0;
  if (mode === "published") {
    categories = parseStrict("categories.json", categoriesFileSchema, rawCategories).contents;
    projects = parseStrict("projects.json", projectsFileSchema, rawProjects).contents;
  } else {
    const c = parseListLenient("categories.json", categorySchema, rawCategories);
    const p = parseListLenient("projects.json", projectSchema, rawProjects);
    categories = c.items;
    projects = p.items;
    dropped += c.dropped + p.dropped;
  }
  const profile = parseObject("profile.json", profileFileSchema, rawProfile, mode);
  const site = parseObject("site.json", siteFileSchema, rawSite, mode);
  dropped += profile.dropped + site.dropped;
  return {
    content: { categories, projects: sortProjects(projects), profile: profile.value, site: site.value },
    dropped,
  };
}
