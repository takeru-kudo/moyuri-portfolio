// Security header definitions for the site and the renderer for the Cloudflare `_headers` file.

export const CSP_HEADER = "Content-Security-Policy-Report-Only";
export const CSP_REPORT_GROUP = "csp";
export const CSP_REPORT_URL = "https://csp.moyuri-kudo.com/report";
export const MEDIA_ORIGIN = "https://media.moyuri-kudo.com";
export const MICROCMS_IMAGE_ORIGIN = "https://images.microcms-assets.io";

/** Placeholder in CSP_DIRECTIVES replaced by the hash sources of the build. */
export const HASHES = "<hashes>";

/** CSP directives in output order. HASHES marks where hash sources are inserted. */
export const CSP_DIRECTIVES: ReadonlyArray<readonly [string, readonly string[]]> = [
  ["default-src", ["'none'"]],
  ["script-src", ["'self'", HASHES]],
  ["style-src", ["'self'", HASHES]],
  ["style-src-attr", ["'unsafe-inline'"]],
  ["img-src", ["'self'", "data:", MICROCMS_IMAGE_ORIGIN]],
  ["media-src", [MEDIA_ORIGIN]],
  ["font-src", ["'self'"]],
  ["connect-src", ["'self'"]],
  ["manifest-src", ["'self'"]],
  ["base-uri", ["'none'"]],
  ["form-action", ["'none'"]],
  ["frame-ancestors", ["'none'"]],
  ["object-src", ["'none'"]],
  ["upgrade-insecure-requests", []],
  ["report-to", [CSP_REPORT_GROUP]],
  ["report-uri", [CSP_REPORT_URL]],
];

/** Headers sent on every path, besides the CSP. */
export const GLOBAL_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ["Reporting-Endpoints", `${CSP_REPORT_GROUP}="${CSP_REPORT_URL}"`],
  ["X-Content-Type-Options", "nosniff"],
  ["Referrer-Policy", "strict-origin-when-cross-origin"],
  [
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  ],
  ["Cross-Origin-Opener-Policy", "same-origin"],
  ["Cross-Origin-Resource-Policy", "same-origin"],
  ["X-Frame-Options", "DENY"],
  ["X-Robots-Tag", "noindex, nofollow"],
];

/** Extra headers for specific path patterns, in output order. */
export const PATH_HEADERS: ReadonlyArray<
  readonly [string, ReadonlyArray<readonly [string, string]>]
> = [
  ["/_astro/*", [["Cache-Control", "public, max-age=31536000, immutable"]]],
  ["/version.txt", [["Cache-Control", "no-store"]]],
];

/** Cloudflare `_headers` limits. */
export const MAX_LINE_LENGTH = 2000;
export const MAX_RULES = 100;

const HASH_SOURCE_RE = /^'sha(256|384|512)-[A-Za-z0-9+/]+={0,2}'$/;

export interface CspHashes {
  script: readonly string[];
  style: readonly string[];
}

/** Returns true when the token is a CSP hash source such as 'sha256-...'. */
export function isHashSource(token: string): boolean {
  return HASH_SOURCE_RE.test(token);
}

function normaliseHashes(hashes: readonly string[]): string[] {
  for (const hash of hashes) {
    if (!isHashSource(hash)) throw new Error("invalid CSP hash source");
  }
  return [...new Set(hashes)].sort();
}

/** Returns the CSP header value with the given hash sources. */
export function buildCsp(hashes: CspHashes): string {
  const byDirective: Record<string, string[]> = {
    "script-src": normaliseHashes(hashes.script),
    "style-src": normaliseHashes(hashes.style),
  };
  return CSP_DIRECTIVES.map(([name, sources]) => {
    const values = sources.flatMap((source) =>
      source === HASHES ? (byDirective[name] ?? []) : [source],
    );
    return [name, ...values].join(" ");
  }).join("; ");
}

/** Parses a CSP header value into a map of directive name -> source list. */
export function parseCsp(value: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter((token) => token !== "");
    const [name, ...sources] = tokens;
    if (name === undefined) continue;
    const key = name.toLowerCase();
    if (!directives.has(key)) directives.set(key, sources);
  }
  return directives;
}

/**
 * Compares a served CSP value with CSP_DIRECTIVES. Hash placeholders match any number of
 * hash sources. Returns a list of mismatch descriptions (empty when the value matches).
 */
export function diffCsp(value: string): string[] {
  const actual = parseCsp(value);
  const problems: string[] = [];
  const expectedNames = CSP_DIRECTIVES.map(([name]) => name);
  for (const name of actual.keys()) {
    if (!expectedNames.includes(name)) problems.push(`unexpected directive ${name}`);
  }
  for (const [name, sources] of CSP_DIRECTIVES) {
    const served = actual.get(name);
    if (served === undefined) {
      problems.push(`missing directive ${name}`);
      continue;
    }
    const fixed = sources.filter((source) => source !== HASHES);
    const servedFixed = served.filter((source) => !isHashSource(source));
    const hashAllowed = sources.includes(HASHES);
    if (servedFixed.join(" ") !== fixed.join(" ")) {
      problems.push(`directive ${name} has sources ${servedFixed.join(" ")}, expected ${fixed.join(" ")}`);
    }
    if (!hashAllowed && served.some(isHashSource)) problems.push(`directive ${name} has hash sources`);
  }
  return problems;
}

/** Collects the script-src and style-src hash sources from a CSP header value. */
export function extractHashes(value: string): CspHashes {
  const directives = parseCsp(value);
  const pick = (name: string) => (directives.get(name) ?? []).filter(isHashSource);
  return { script: pick("script-src"), style: pick("style-src") };
}

/** Merges several hash sets into one. */
export function mergeHashes(sets: Iterable<CspHashes>): CspHashes {
  const script = new Set<string>();
  const style = new Set<string>();
  for (const set of sets) {
    for (const hash of set.script) script.add(hash);
    for (const hash of set.style) style.add(hash);
  }
  return { script: [...script].sort(), style: [...style].sort() };
}

/** Returns every header for "/*" in output order, including the CSP. */
export function globalHeaders(hashes: CspHashes): Array<readonly [string, string]> {
  return [[CSP_HEADER, buildCsp(hashes)], ...GLOBAL_HEADERS];
}

function assertSafe(text: string): void {
  if (/[\r\n]/.test(text)) throw new Error("header text contains a line break");
}

/** Renders the Cloudflare `_headers` file. Throws when a Cloudflare limit is exceeded. */
export function renderHeadersFile(hashes: CspHashes): string {
  const rules: Array<readonly [string, ReadonlyArray<readonly [string, string]>]> = [
    ["/*", globalHeaders(hashes)],
    ...PATH_HEADERS,
  ];
  if (rules.length > MAX_RULES) throw new Error("too many _headers rules");
  const lines: string[] = [];
  for (const [path, headers] of rules) {
    if (lines.length > 0) lines.push("");
    lines.push(path);
    for (const [name, value] of headers) lines.push(`  ${name}: ${value}`);
  }
  for (const line of lines) {
    assertSafe(line);
    if (line.length > MAX_LINE_LENGTH) throw new Error("a _headers line exceeds the length limit");
  }
  return `${lines.join("\n")}\n`;
}
