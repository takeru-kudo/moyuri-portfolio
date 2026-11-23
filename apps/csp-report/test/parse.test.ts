import { describe, expect, it } from "vitest";
import {
  documentPathOf,
  extractReports,
  MAX_BLOCKED_ORIGIN,
  MAX_DIRECTIVE,
  MAX_DOCUMENT_PATH,
  normalise,
  normaliseBlocked,
  type RawReport,
  reportFormat,
} from "../src/parse.ts";

function raw(overrides: Partial<RawReport> = {}): RawReport {
  return {
    documentUrl: "https://moyuri-kudo.com/works/a?x=1",
    blockedUrl: "https://cdn.example.com/a.js?q=1",
    effectiveDirective: "script-src-elem",
    violatedDirective: undefined,
    sourceFile: undefined,
    ...overrides,
  };
}

describe("reportFormat", () => {
  it.each([
    ["application/reports+json", "reports+json"],
    ["Application/Reports+JSON; charset=utf-8", "reports+json"],
    ["application/csp-report", "csp-report"],
    ["application/json", undefined],
    ["text/plain", undefined],
    [null, undefined],
  ])("%s -> %s", (header, expected) => {
    expect(reportFormat(header)).toBe(expected);
  });
});

describe("extractReports", () => {
  it("reads csp-violation entries and skips other report types", () => {
    const reports = extractReports("reports+json", [
      { type: "csp-violation", body: { documentURL: "d", blockedURL: "b", effectiveDirective: "img-src" } },
      { type: "deprecation", body: {} },
      "junk",
    ]);
    expect(reports).toHaveLength(1);
    expect(reports?.[0]?.effectiveDirective).toBe("img-src");
  });

  it("reads the legacy csp-report shape", () => {
    const reports = extractReports("csp-report", {
      "csp-report": { "document-uri": "d", "blocked-uri": "b", "violated-directive": "img-src 'self'" },
    });
    expect(reports?.[0]?.violatedDirective).toBe("img-src 'self'");
  });

  it.each([
    ["reports+json", { type: "csp-violation" }],
    ["csp-report", []],
    ["csp-report", { other: {} }],
    ["csp-report", null],
  ] as const)("rejects a %s body of the wrong shape", (format, body) => {
    expect(extractReports(format, body)).toBeUndefined();
  });
});

describe("normaliseBlocked", () => {
  it.each([
    ["https://cdn.example.com:8443/path/a.js?q=1#f", "https://cdn.example.com:8443"],
    ["HTTPS://User:Pass@CDN.Example.com/x", "https://cdn.example.com"],
    ["wss://ws.example.com/socket", "wss://ws.example.com"],
    ["data:image/png;base64,AAAA", "data:"],
    ["blob:https://moyuri-kudo.com/uuid", "blob:"],
    ["inline", "inline"],
    ["eval", "eval"],
    ["trusted-types-sink", "trusted-types-sink"],
    ["", ""],
    [undefined, ""],
    [42, ""],
  ])("%s -> %s", (input, expected) => {
    expect(normaliseBlocked(input)).toBe(expected);
  });

  it("truncates long values", () => {
    expect(normaliseBlocked(`https://${"a".repeat(300)}.example.com/`)).toHaveLength(MAX_BLOCKED_ORIGIN);
    expect(normaliseBlocked("k".repeat(300))).toHaveLength(MAX_BLOCKED_ORIGIN);
  });
});

describe("documentPathOf", () => {
  it.each([
    ["https://moyuri-kudo.com/works/a?x=1#top", "/works/a"],
    ["https://moyuri-kudo.com", "/"],
    ["https://beta.moyuri-kudo.com/", undefined],
    ["http://moyuri-kudo.com/", undefined],
    ["https://moyuri-kudo.com.evil.example/", undefined],
    ["not a url", undefined],
    [null, undefined],
  ])("%s -> %s", (input, expected) => {
    expect(documentPathOf(input)).toBe(expected);
  });

  it("truncates long paths", () => {
    expect(documentPathOf(`https://moyuri-kudo.com/${"p".repeat(400)}`)).toHaveLength(MAX_DOCUMENT_PATH);
  });
});

describe("normalise", () => {
  it("builds the storage key", () => {
    expect(normalise(raw())).toEqual({
      kind: "ok",
      key: { directive: "script-src-elem", blockedOrigin: "https://cdn.example.com", documentPath: "/works/a" },
    });
  });

  it("falls back to the first token of violated-directive", () => {
    const result = normalise(raw({ effectiveDirective: undefined, violatedDirective: "Style-Src 'self'" }));
    expect(result).toMatchObject({ kind: "ok", key: { directive: "style-src" } });
  });

  it("truncates the directive", () => {
    const result = normalise(raw({ effectiveDirective: "d".repeat(100) }));
    expect(result.kind === "ok" && result.key.directive).toHaveLength(MAX_DIRECTIVE);
  });

  it.each([
    ["chrome-extension://abc/script.js", undefined],
    ["moz-extension://abc/x", undefined],
    ["safari-web-extension://abc/x", undefined],
    ["inline", "chrome-extension://abc/content.js"],
    ["inline", "Safari-Extension://abc/content.js"],
  ])("excludes extension reports (blocked %s, source %s)", (blockedUrl, sourceFile) => {
    expect(normalise(raw({ blockedUrl, sourceFile }))).toEqual({ kind: "excluded" });
  });

  it("excludes reports from other documents", () => {
    expect(normalise(raw({ documentUrl: "https://example.com/" }))).toEqual({ kind: "excluded" });
  });

  it("marks reports without a document or directive as invalid", () => {
    expect(normalise(raw({ documentUrl: undefined }))).toEqual({ kind: "invalid" });
    expect(normalise(raw({ effectiveDirective: undefined }))).toEqual({ kind: "invalid" });
    expect(normalise(raw({ effectiveDirective: "  " }))).toEqual({ kind: "invalid" });
  });
});
