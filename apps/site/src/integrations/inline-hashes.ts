// Finds inline <script>/<style> contents in built HTML and checks their sha256 against CSP hashes.

import { createHash } from "node:crypto";
import { CSP_HEADER, extractHashes, type CspHashes } from "@portfolio/security-headers";

/** Top-level HTML comments, scripts and styles, scanned in document order. */
const TOKEN_RE =
  /<!--[\s\S]*?(?:-->|$)|<(script|style)((?:\s[^>]*)?)>([\s\S]*?)<\/\1\s*>/gi;
const ATTRIBUTE_RE = /([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;

/** Script types whose inline content is subject to CSP script-src. */
const CSP_SCRIPT_TYPES = new Set([
  "",
  "module",
  "importmap",
  "speculationrules",
  "application/ecmascript",
  "application/javascript",
  "application/x-ecmascript",
  "application/x-javascript",
  "text/ecmascript",
  "text/javascript",
  "text/javascript1.0",
  "text/javascript1.1",
  "text/javascript1.2",
  "text/javascript1.3",
  "text/javascript1.4",
  "text/javascript1.5",
  "text/jscript",
  "text/livescript",
  "text/x-ecmascript",
  "text/x-javascript",
]);

export interface InlineHashes {
  script: string[];
  style: string[];
}

export interface MissingCounts {
  script: number;
  style: number;
}

export interface CoverageResult extends MissingCounts {
  pages: number;
}

/** Returns the CSP hash source ('sha256-<base64>') of a string. */
export function sha256Source(content: string): string {
  return `'sha256-${createHash("sha256").update(content, "utf8").digest("base64")}'`;
}

/** Parses an attribute string into a map of lower-cased name -> first value. */
export function parseAttributes(text: string): Map<string, string> {
  const attributes = new Map<string, string>();
  for (const match of text.matchAll(ATTRIBUTE_RE)) {
    const name = match[1]!.toLowerCase();
    if (!attributes.has(name)) attributes.set(name, match[2] ?? match[3] ?? match[4] ?? "");
  }
  return attributes;
}

function isCspScript(attributeText: string): boolean {
  const attributes = parseAttributes(attributeText);
  if (attributes.has("src")) return false;
  const type = (attributes.get("type") ?? "").trim().toLowerCase();
  return CSP_SCRIPT_TYPES.has(type);
}

/** Returns the hash sources of every top-level inline script and style in an HTML document. */
export function findInlineHashes(html: string): InlineHashes {
  const script: string[] = [];
  const style: string[] = [];
  for (const [, tag, attributes, body] of html.matchAll(TOKEN_RE)) {
    if (tag === undefined) continue;
    if (tag.toLowerCase() === "style") style.push(sha256Source(body ?? ""));
    else if (isCspScript(attributes ?? "")) script.push(sha256Source(body ?? ""));
  }
  return { script, style };
}

/** Counts inline scripts and styles whose hash is not in the allowed hash sets. */
export function countMissing(found: InlineHashes, allowed: CspHashes): MissingCounts {
  const scripts = new Set(allowed.script);
  const styles = new Set(allowed.style);
  return {
    script: found.script.filter((hash) => !scripts.has(hash)).length,
    style: found.style.filter((hash) => !styles.has(hash)).length,
  };
}

/** Returns the script-src and style-src hashes of the CSP line in a rendered _headers file. */
export function hashesInHeadersFile(text: string): CspHashes {
  const prefix = `  ${CSP_HEADER}: `;
  const line = text.split("\n").find((candidate) => candidate.startsWith(prefix));
  if (line === undefined) throw new Error("the CSP line is missing from _headers");
  return extractHashes(line.slice(prefix.length));
}

/** Totals the uncovered inline scripts and styles over several HTML documents. */
export function checkCoverage(documents: Iterable<string>, allowed: CspHashes): CoverageResult {
  const result: CoverageResult = { pages: 0, script: 0, style: 0 };
  for (const html of documents) {
    const missing = countMissing(findInlineHashes(html), allowed);
    if (missing.script + missing.style === 0) continue;
    result.pages += 1;
    result.script += missing.script;
    result.style += missing.style;
  }
  return result;
}

/** Returns the build error message for uncovered inline content (counts only), or null. */
export function coverageError(result: CoverageResult): string | null {
  if (result.pages === 0) return null;
  return `${result.script} inline script(s) and ${result.style} inline style(s) on ${result.pages} page(s) are not covered by the CSP hashes`;
}
