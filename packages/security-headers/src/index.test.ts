import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  CSP_DIRECTIVES,
  CSP_HEADER,
  HASHES,
  MAX_LINE_LENGTH,
  buildCsp,
  diffCsp,
  extractHashes,
  isHashSource,
  mergeHashes,
  parseCsp,
  renderHeadersFile,
} from "./index.ts";

const H1 = "'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='";
const H2 = "'sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='";
const NONE = { script: [], style: [] };

describe("isHashSource", () => {
  it("accepts sha256/384/512 sources", () => {
    assert.equal(isHashSource(H1), true);
    assert.equal(isHashSource("'sha384-abc+/='"), true);
    assert.equal(isHashSource("'sha512-abc'"), true);
  });

  it("rejects other tokens", () => {
    for (const token of ["'self'", "sha256-abc", "'sha1-abc'", "'sha256-a b'", "'sha256-a'; x"]) {
      assert.equal(isHashSource(token), false, token);
    }
  });
});

describe("buildCsp", () => {
  it("renders the directives without hashes", () => {
    assert.equal(
      buildCsp(NONE),
      "default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; " +
        "img-src 'self' data: https://images.microcms-assets.io; media-src https://media.moyuri-kudo.com; font-src 'self'; " +
        "connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; " +
        "frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests; report-to csp; " +
        "report-uri https://csp.moyuri-kudo.com/report",
    );
  });

  it("inserts sorted, de-duplicated hashes into script-src and style-src only", () => {
    const csp = parseCsp(buildCsp({ script: [H2, H1, H2], style: [H1] }));
    assert.deepEqual(csp.get("script-src"), ["'self'", H1, H2]);
    assert.deepEqual(csp.get("style-src"), ["'self'", H1]);
    assert.deepEqual(csp.get("style-src-attr"), ["'unsafe-inline'"]);
    assert.deepEqual(csp.get("default-src"), ["'none'"]);
  });

  it("rejects invalid hash sources", () => {
    assert.throws(() => buildCsp({ script: ["'unsafe-inline'"], style: [] }));
    assert.throws(() => buildCsp({ script: [], style: ["'sha256-a'\n/*"] }));
  });

  it("has no Web Analytics origins", () => {
    assert.equal(buildCsp(NONE).includes("cloudflareinsights"), false);
  });

  it("places the hash placeholder only in script-src and style-src", () => {
    const withPlaceholder = CSP_DIRECTIVES.filter(([, sources]) => sources.includes(HASHES));
    assert.deepEqual(
      withPlaceholder.map(([name]) => name),
      ["script-src", "style-src"],
    );
  });
});

describe("parseCsp", () => {
  it("lower-cases names, keeps the first duplicate and skips empty parts", () => {
    const csp = parseCsp(" Script-Src 'self'  a ;; script-src b; upgrade-insecure-requests ");
    assert.deepEqual(csp.get("script-src"), ["'self'", "a"]);
    assert.deepEqual(csp.get("upgrade-insecure-requests"), []);
    assert.equal(csp.size, 2);
  });
});

describe("diffCsp", () => {
  it("accepts the built policy with or without hashes", () => {
    assert.deepEqual(diffCsp(buildCsp(NONE)), []);
    assert.deepEqual(diffCsp(buildCsp({ script: [H1, H2], style: [H1] })), []);
  });

  it("reports missing, extra and changed directives", () => {
    const csp = buildCsp(NONE)
      .replace("frame-ancestors 'none'; ", "")
      .replace("img-src 'self' data: https://images.microcms-assets.io", "img-src *")
      .concat("; worker-src 'self'");
    assert.deepEqual(diffCsp(csp).sort(), [
      "directive img-src has sources *, expected 'self' data: https://images.microcms-assets.io",
      "missing directive frame-ancestors",
      "unexpected directive worker-src",
    ]);
  });

  it("rejects hash sources outside script-src and style-src", () => {
    const csp = buildCsp(NONE).replace("img-src 'self' data:", `img-src 'self' data: ${H1}`);
    assert.deepEqual(diffCsp(csp), ["directive img-src has hash sources"]);
  });

  it("rejects 'unsafe-inline' added to script-src", () => {
    const csp = buildCsp(NONE).replace("script-src 'self'", "script-src 'self' 'unsafe-inline'");
    assert.equal(diffCsp(csp).length, 1);
  });
});

describe("extractHashes", () => {
  it("returns hash sources of script-src and style-src", () => {
    const value = `script-src 'self' ${H1}; style-src 'self' ${H2} 'unsafe-inline'; img-src ${H1}`;
    assert.deepEqual(extractHashes(value), { script: [H1], style: [H2] });
  });

  it("returns empty lists when there are no hashes", () => {
    assert.deepEqual(extractHashes("script-src 'self'; style-src 'self'"), NONE);
  });
});

describe("mergeHashes", () => {
  it("unions and sorts", () => {
    assert.deepEqual(
      mergeHashes([
        { script: [H2], style: [] },
        { script: [H1, H2], style: [H2] },
      ]),
      { script: [H1, H2], style: [H2] },
    );
  });
});

describe("renderHeadersFile", () => {
  it("renders the rules", () => {
    const text = renderHeadersFile({ script: [H1], style: [] });
    const lines = text.split("\n");
    assert.equal(lines[0], "/*");
    assert.equal(lines[1], `  ${CSP_HEADER}: ${buildCsp({ script: [H1], style: [] })}`);
    assert.ok(lines.includes('  Reporting-Endpoints: csp="https://csp.moyuri-kudo.com/report"'));
    assert.ok(lines.includes("  X-Content-Type-Options: nosniff"));
    assert.ok(lines.includes("  X-Robots-Tag: noindex, nofollow"));
    assert.ok(lines.includes("  X-Frame-Options: DENY"));
    assert.match(text, /\n\/_astro\/\*\n {2}Cache-Control: public, max-age=31536000, immutable\n/);
    assert.match(text, /\n\/version\.txt\n {2}Cache-Control: no-store\n$/);
    assert.equal(text.includes("Content-Security-Policy:"), false);
  });

  it("fails when the CSP line exceeds the Cloudflare limit", () => {
    const many = Array.from({ length: 60 }, (_, i) => `'sha256-${String(i).padStart(43, "A")}='`);
    assert.throws(() => renderHeadersFile({ script: many, style: [] }), /length limit/);
    assert.ok(MAX_LINE_LENGTH === 2000);
  });
});
