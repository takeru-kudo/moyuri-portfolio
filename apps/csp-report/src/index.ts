// csp-report: receives CSP violation reports and counts them in D1.

import { readBodyWithLimit } from "./body.ts";
import { extractReports, normalise, type RawReport, type ReportKey, reportFormat, SITE_ORIGIN } from "./parse.ts";
import { deleteOldRows, storeReports } from "./store.ts";

export interface Env {
  DB: D1Database;
  CF_VERSION_METADATA: WorkerVersionMetadata;
}

export const MAX_KEYS_PER_REQUEST = 40;

const BASE_HEADERS = { "Cache-Control": "no-store" };

function log(fields: Record<string, unknown>): void {
  console.log(JSON.stringify(fields));
}

function json(status: number, body: unknown, extra: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...BASE_HEADERS, "Content-Type": "application/json", ...extra },
  });
}

function corsHeaders(request: Request): Record<string, string> {
  if (request.headers.get("origin") !== SITE_ORIGIN) {
    return { Vary: "Origin" };
  }
  return { "Access-Control-Allow-Origin": SITE_ORIGIN, Vary: "Origin" };
}

function empty(status: number, extra: HeadersInit = {}): Response {
  return new Response(null, { status, headers: { ...BASE_HEADERS, ...extra } });
}

function preflight(request: Request): Response {
  const method = request.headers.get("access-control-request-method");
  if (request.headers.get("origin") !== SITE_ORIGIN || method !== "POST") {
    return empty(403, { Vary: "Origin" });
  }
  return empty(204, {
    "Access-Control-Allow-Origin": SITE_ORIGIN,
    "Access-Control-Allow-Methods": "POST",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  });
}

function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return undefined;
  }
}

/** Groups normalised keys and counts outcomes; reports with keys beyond MAX_KEYS_PER_REQUEST are counted as dropped. */
function collect(reports: RawReport[]) {
  const counts = new Map<string, [ReportKey, number]>();
  let excluded = 0;
  let invalid = 0;
  let dropped = 0;
  for (const report of reports) {
    const result = normalise(report);
    if (result.kind !== "ok") {
      if (result.kind === "excluded") {
        excluded += 1;
      } else {
        invalid += 1;
      }
      continue;
    }
    const id = JSON.stringify([result.key.directive, result.key.blockedOrigin, result.key.documentPath]);
    const entry = counts.get(id);
    if (entry !== undefined) {
      entry[1] += 1;
    } else if (counts.size < MAX_KEYS_PER_REQUEST) {
      counts.set(id, [result.key, 1]);
    } else {
      dropped += 1;
    }
  }
  return { entries: [...counts.values()], excluded, invalid, dropped };
}

async function store(db: D1Database, entries: [ReportKey, number][], dropped: number, nowMs: number): Promise<void> {
  try {
    const result = await storeReports(db, entries, dropped, nowMs);
    log({ event: "store", outcome: "ok", stored: result.stored, overflow: result.overflow });
  } catch {
    log({ event: "store", outcome: "error", keys: entries.length });
  }
}

async function handleReport(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const cors = corsHeaders(request);
  const format = reportFormat(request.headers.get("content-type"));
  if (format === undefined) {
    log({ event: "report", outcome: "unsupported_type", status: 415 });
    return empty(415, cors);
  }
  const body = await readBodyWithLimit(request);
  if (!body.ok) {
    const status = body.reason === "too_large" ? 413 : 400;
    log({ event: "report", outcome: body.reason, status });
    return empty(status, cors);
  }
  const reports = extractReports(format, parseJson(body.bytes));
  if (reports === undefined) {
    log({ event: "report", outcome: "malformed", status: 400 });
    return empty(400, cors);
  }
  const { entries, excluded, invalid, dropped } = collect(reports);
  log({
    event: "report",
    outcome: entries.length > 0 ? "accepted" : "ignored",
    status: 204,
    format,
    reports: reports.length,
    keys: entries.length,
    excluded,
    invalid,
    dropped,
  });
  if (entries.length > 0 || dropped > 0) {
    ctx.waitUntil(store(env.DB, entries, dropped, Date.now()));
  }
  return empty(204, cors);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === "/report") {
      if (request.method === "OPTIONS") {
        return preflight(request);
      }
      if (request.method !== "POST") {
        return json(405, { error: "method_not_allowed" }, { Allow: "POST, OPTIONS" });
      }
      try {
        return await handleReport(request, env, ctx);
      } catch {
        log({ event: "report", outcome: "error", status: 500 });
        return empty(500);
      }
    }
    if (pathname === "/healthz") {
      if (request.method !== "GET") {
        return json(405, { error: "method_not_allowed" }, { Allow: "GET" });
      }
      return json(200, { status: "ok", version: env.CF_VERSION_METADATA.id });
    }
    return json(404, { error: "not_found" });
  },

  async scheduled(controller: ScheduledController, env: Env): Promise<void> {
    try {
      const result = await deleteOldRows(env.DB, controller.scheduledTime);
      log({ event: "cleanup", outcome: "ok", violations: result.violations, overflow: result.overflow });
    } catch (error) {
      log({ event: "cleanup", outcome: "error" });
      throw error;
    }
  },
} satisfies ExportedHandler<Env>;
