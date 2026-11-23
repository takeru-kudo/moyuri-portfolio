// Parses CSP report bodies and normalises each report to a storage key.

export const SITE_ORIGIN = "https://moyuri-kudo.com";
export const MAX_DIRECTIVE = 64;
export const MAX_BLOCKED_ORIGIN = 256;
export const MAX_DOCUMENT_PATH = 256;

export type ReportFormat = "reports+json" | "csp-report";

const EXTENSION_SCHEMES = new Set([
  "chrome-extension",
  "moz-extension",
  "safari-extension",
  "safari-web-extension",
  "ms-browser-extension",
  "edge-extension",
  "extension",
]);
const ORIGIN_SCHEMES = new Set(["http", "https", "ws", "wss"]);
const SCHEME_RE = /^([a-z][a-z0-9+.-]*):/i;

export interface ReportKey {
  directive: string;
  blockedOrigin: string;
  documentPath: string;
}

export type Normalised = { kind: "ok"; key: ReportKey } | { kind: "excluded" } | { kind: "invalid" };

export interface RawReport {
  documentUrl: unknown;
  blockedUrl: unknown;
  effectiveDirective: unknown;
  violatedDirective: unknown;
  sourceFile: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Returns the media type of a Content-Type header value, or undefined when it is not a report format. */
export function reportFormat(contentType: string | null): ReportFormat | undefined {
  const media = (contentType ?? "").split(";")[0]?.trim().toLowerCase();
  if (media === "application/reports+json") {
    return "reports+json";
  }
  if (media === "application/csp-report") {
    return "csp-report";
  }
  return undefined;
}

/** Extracts raw CSP reports from a parsed body; undefined when the body shape is not a report body. */
export function extractReports(format: ReportFormat, payload: unknown): RawReport[] | undefined {
  if (format === "csp-report") {
    if (!isRecord(payload) || !isRecord(payload["csp-report"])) {
      return undefined;
    }
    const r = payload["csp-report"];
    return [
      {
        documentUrl: r["document-uri"],
        blockedUrl: r["blocked-uri"],
        effectiveDirective: r["effective-directive"],
        violatedDirective: r["violated-directive"],
        sourceFile: r["source-file"],
      },
    ];
  }
  if (!Array.isArray(payload)) {
    return undefined;
  }
  const reports: RawReport[] = [];
  for (const item of payload) {
    if (!isRecord(item) || item.type !== "csp-violation" || !isRecord(item.body)) {
      continue;
    }
    const b = item.body;
    reports.push({
      documentUrl: b.documentURL,
      blockedUrl: b.blockedURL,
      effectiveDirective: b.effectiveDirective,
      violatedDirective: b.violatedDirective,
      sourceFile: b.sourceFile,
    });
  }
  return reports;
}

function schemeOf(value: string): string | undefined {
  return SCHEME_RE.exec(value)?.[1]?.toLowerCase();
}

function isExtensionUrl(value: unknown): boolean {
  if (typeof value !== "string") {
    return false;
  }
  const scheme = schemeOf(value.trim());
  return scheme !== undefined && EXTENSION_SCHEMES.has(scheme);
}

function normaliseDirective(effective: unknown, violated: unknown): string | undefined {
  const source = typeof effective === "string" && effective.trim() !== "" ? effective : violated;
  if (typeof source !== "string") {
    return undefined;
  }
  const directive = source.trim().split(/\s+/)[0]?.toLowerCase() ?? "";
  return directive === "" ? undefined : directive.slice(0, MAX_DIRECTIVE);
}

/** Scheme and host for URL-like values, the scheme alone for other schemes, keywords unchanged. */
export function normaliseBlocked(value: unknown): string {
  if (typeof value !== "string") {
    return "";
  }
  const trimmed = value.trim();
  const scheme = schemeOf(trimmed);
  if (scheme === undefined) {
    return trimmed.slice(0, MAX_BLOCKED_ORIGIN);
  }
  if (ORIGIN_SCHEMES.has(scheme)) {
    try {
      const url = new URL(trimmed);
      return `${url.protocol}//${url.host}`.slice(0, MAX_BLOCKED_ORIGIN);
    } catch {
      return `${scheme}:`;
    }
  }
  return `${scheme}:`.slice(0, MAX_BLOCKED_ORIGIN);
}

/** Path of a document URL on the site origin; undefined for any other origin or an unparsable URL. */
export function documentPathOf(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    return undefined;
  }
  if (url.origin !== SITE_ORIGIN) {
    return undefined;
  }
  return url.pathname.slice(0, MAX_DOCUMENT_PATH);
}

/** Normalises one raw report: excluded for extension-caused or foreign-document reports, invalid when fields are missing. */
export function normalise(report: RawReport): Normalised {
  if (isExtensionUrl(report.blockedUrl) || isExtensionUrl(report.sourceFile)) {
    return { kind: "excluded" };
  }
  if (typeof report.documentUrl !== "string") {
    return { kind: "invalid" };
  }
  const documentPath = documentPathOf(report.documentUrl);
  if (documentPath === undefined) {
    return { kind: "excluded" };
  }
  const directive = normaliseDirective(report.effectiveDirective, report.violatedDirective);
  if (directive === undefined) {
    return { kind: "invalid" };
  }
  return { kind: "ok", key: { directive, blockedOrigin: normaliseBlocked(report.blockedUrl), documentPath } };
}
