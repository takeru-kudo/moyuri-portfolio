// Astro integration that writes dist/_headers from @portfolio/security-headers.
// Script and style hashes come from Astro's security.csp, delivered as per-route
// response headers through the staticHeaders adapter feature (no <meta> CSP).

import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AstroIntegration } from "astro";
import {
  extractHashes,
  mergeHashes,
  renderHeadersFile,
  type CspHashes,
} from "@portfolio/security-headers";
import { checkCoverage, coverageError, hashesInHeadersFile } from "./inline-hashes.ts";

const NAME = "@portfolio/security-headers";
const CSP_META_RE = /<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy/i;

async function listHtmlFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".html"))
    .map((entry) => path.join(entry.parentPath, entry.name));
}

/** Fails when any built page still carries a <meta> CSP; reports a count only. */
async function assertNoMetaCsp(dir: string): Promise<void> {
  let count = 0;
  for (const file of await listHtmlFiles(dir)) {
    if (CSP_META_RE.test(await readFile(file, "utf8"))) count += 1;
  }
  if (count > 0) throw new Error(`${NAME}: ${count} page(s) contain a <meta> CSP`);
}

/** Fails when an inline script or style in a built page is not covered by the CSP hashes; counts only. */
async function assertInlineHashesCovered(dir: string, headersFile: string): Promise<void> {
  const documents: string[] = [];
  for (const file of await listHtmlFiles(dir)) documents.push(await readFile(file, "utf8"));
  const message = coverageError(checkCoverage(documents, hashesInHeadersFile(headersFile)));
  if (message !== null) throw new Error(`${NAME}: ${message}`);
}

export function securityHeaders(): AstroIntegration {
  let hashes: CspHashes | undefined;
  let routes = 0;
  return {
    name: NAME,
    hooks: {
      "astro:config:done": ({ setAdapter }) => {
        setAdapter({
          name: NAME,
          entrypointResolution: "auto",
          supportedAstroFeatures: { staticOutput: "stable", sharpImageService: "stable" },
          adapterFeatures: { buildOutput: "static", staticHeaders: true },
        });
      },
      "astro:build:generated": ({ routeToHeaders }) => {
        const sets: CspHashes[] = [];
        for (const { headers } of routeToHeaders.values()) {
          const csp = headers.get("content-security-policy");
          if (csp === null) throw new Error(`${NAME}: a route has no CSP header from Astro`);
          sets.push(extractHashes(csp));
        }
        routes = sets.length;
        hashes = mergeHashes(sets);
      },
      "astro:build:done": async ({ dir, logger }) => {
        if (hashes === undefined || routes === 0) {
          throw new Error(`${NAME}: no route headers were collected`);
        }
        const outDir = fileURLToPath(dir);
        await assertNoMetaCsp(outDir);
        const headersFile = renderHeadersFile(hashes);
        await assertInlineHashesCovered(outDir, headersFile);
        await writeFile(path.join(outDir, "_headers"), headersFile);
        logger.info(
          `_headers written: ${routes} route(s), ${hashes.script.length} script hash(es), ${hashes.style.length} style hash(es)`,
        );
      },
    },
  };
}
