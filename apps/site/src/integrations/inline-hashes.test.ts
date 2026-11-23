import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";

import { renderHeadersFile } from "@portfolio/security-headers";

import {
  checkCoverage,
  countMissing,
  coverageError,
  findInlineHashes,
  hashesInHeadersFile,
  parseAttributes,
  sha256Source,
} from "./inline-hashes.ts";

const hash = (text: string) => `'sha256-${createHash("sha256").update(text).digest("base64")}'`;

describe("sha256Source", () => {
  it("matches the CSP hash source format", () => {
    assert.equal(sha256Source('console.log("p5a")'), "'sha256-0VaQWUyEZELcV3r2frjJlKJKo8cr43nTteZRsm8t0fc='");
    assert.equal(sha256Source("body{margin:0}"), "'sha256-IAdwN3biDCQ3brrgp1m8kBEsPQYyqfREKOEfeoREopc='");
  });

  it("hashes UTF-8 bytes", () => {
    assert.equal(sha256Source("// 日本語"), hash("// 日本語"));
  });
});

describe("findInlineHashes", () => {
  it("returns nothing for a page without inline content", () => {
    assert.deepEqual(findInlineHashes("<html><head><title>t</title></head><body><p>x</p></body></html>"), {
      script: [],
      style: [],
    });
  });

  it("hashes inline scripts and styles exactly as written", () => {
    const html = '<script>a()</script><SCRIPT type="module">\n b()\n</SCRIPT ><style media="print">p{}</style>';
    assert.deepEqual(findInlineHashes(html), {
      script: [hash("a()"), hash("\n b()\n")],
      style: [hash("p{}")],
    });
  });

  it("skips external scripts and non-executable data blocks", () => {
    const html =
      '<script src="/_astro/a.js"></script><script type="module" src=/x.js></script>' +
      '<script type="application/ld+json">{"a":1}</script><script type="text/plain">x</script>';
    assert.deepEqual(findInlineHashes(html).script, []);
  });

  it("checks script types that CSP applies to", () => {
    const html =
      "<script type='text/javascript'>a</script><script type=importmap>{}</script>" +
      '<script type="speculationrules">{}</script><script type="">b</script>';
    assert.deepEqual(findInlineHashes(html).script, [hash("a"), hash("{}"), hash("{}"), hash("b")]);
  });

  it("does not treat data-src or type-like attributes as src/type", () => {
    const html = '<script data-src="x" data-type="text/plain">c()</script>';
    assert.deepEqual(findInlineHashes(html).script, [hash("c()")]);
  });

  it("hashes empty inline elements", () => {
    assert.deepEqual(findInlineHashes("<script></script><style></style>"), {
      script: [hash("")],
      style: [hash("")],
    });
  });

  it("checks legacy JavaScript MIME types", () => {
    const types = ["text/jscript", "text/javascript1.5", "application/x-javascript", "TEXT/X-ECMASCRIPT"];
    const html = types.map((type) => `<script type="${type}">d()</script>`).join("");
    assert.equal(findInlineHashes(html).script.length, types.length);
  });

  it("ignores src= and type= inside other attribute values", () => {
    const html =
      '<script data-x="a src=b">e()</script>' +
      "<script data-y=' type=text/plain'>f()</script>" +
      '<script nonce="x" type="text/plain" type="module">g()</script>';
    assert.deepEqual(findInlineHashes(html).script, [hash("e()"), hash("f()")]);
  });

  it("skips tags inside HTML comments and style tags inside script bodies", () => {
    const html =
      "<!-- <script>h()</script> <style>p{}</style> -->" +
      '<script>document.write("<style>q{}</style>")</script><!-- unterminated <style>r{}</style>';
    assert.deepEqual(findInlineHashes(html), {
      script: [hash('document.write("<style>q{}</style>")')],
      style: [],
    });
  });
});

describe("parseAttributes", () => {
  it("reads quoted, unquoted and bare attributes with lower-cased names", () => {
    const attributes = parseAttributes(' TYPE=module defer data-a="x y" data-b=\'z\'');
    assert.deepEqual([...attributes], [
      ["type", "module"],
      ["defer", ""],
      ["data-a", "x y"],
      ["data-b", "z"],
    ]);
  });

  it("keeps the first value of a duplicated attribute", () => {
    assert.equal(parseAttributes(' type="a" type="b"').get("type"), "a");
  });
});

describe("countMissing", () => {
  it("counts every occurrence whose hash is not allowed", () => {
    const found = { script: [hash("a"), hash("b"), hash("b")], style: [hash("s")] };
    assert.deepEqual(countMissing(found, { script: [hash("a")], style: [] }), { script: 2, style: 1 });
  });

  it("returns zero when everything is covered", () => {
    const found = { script: [hash("a")], style: [hash("s")] };
    assert.deepEqual(countMissing(found, { script: [hash("a")], style: [hash("s")] }), { script: 0, style: 0 });
  });

  it("does not accept a script hash listed only under style-src", () => {
    const found = { script: [hash("a")], style: [] };
    assert.deepEqual(countMissing(found, { script: [], style: [hash("a")] }), { script: 1, style: 0 });
  });
});

describe("hashesInHeadersFile", () => {
  it("reads the hashes back from a rendered _headers file", () => {
    const file = renderHeadersFile({ script: [hash("a"), hash("b")], style: [hash("s")] });
    assert.deepEqual(hashesInHeadersFile(file), {
      script: [hash("a"), hash("b")].sort(),
      style: [hash("s")],
    });
  });

  it("throws when the CSP line is missing", () => {
    assert.throws(() => hashesInHeadersFile("/*\n  X-Frame-Options: DENY\n"), /CSP line is missing/);
  });
});

describe("checkCoverage and coverageError", () => {
  const allowed = { script: [hash("ok()")], style: [] };

  it("returns no error when every page is covered", () => {
    const result = checkCoverage(["<script>ok()</script>", "<p>x</p>"], allowed);
    assert.deepEqual(result, { pages: 0, script: 0, style: 0 });
    assert.equal(coverageError(result), null);
  });

  it("reports counts only", () => {
    const pages = [
      "<script>ok()</script><script>secret_slug()</script><style>.secret{}</style>",
      "<style>.other{}</style>",
      "<script>ok()</script>",
    ];
    const result = checkCoverage(pages, allowed);
    assert.deepEqual(result, { pages: 2, script: 1, style: 2 });
    const message = coverageError(result);
    assert.equal(
      message,
      "1 inline script(s) and 2 inline style(s) on 2 page(s) are not covered by the CSP hashes",
    );
    assert.doesNotMatch(message ?? "", /secret|other|sha256/);
  });
});
