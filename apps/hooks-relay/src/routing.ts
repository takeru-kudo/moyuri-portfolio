// Decides the deploy target and the dispatch reason for a microCMS webhook body.

export type Target = "beta" | "prod";
export type Decision = "publish" | "draft" | "unknown";

export const REASON_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]+$/;
const STATUSES = new Set(["PUBLISH", "DRAFT", "CLOSED"]);

export interface RouteInput {
  api: string | undefined;
  id: string | undefined;
  decision: Decision;
}

/** Which prod reason was used: the full one, without the content ID, or the decision alone. */
export type Fallback = "none" | "without_id" | "decision_only";

export type RouteResult =
  | {
      ok: true;
      target: Target;
      reason: string;
      decision: Decision;
      fallback: Fallback;
      api: string | undefined;
      id: string | undefined;
    }
  | { ok: false; decision: Decision; api: string | undefined; id: string | undefined };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Returns the status array of a contents.old/new entry, null for a null entry, undefined when the shape is unexpected. */
function readStatus(entry: unknown): string[] | null | undefined {
  if (entry === null) {
    return null;
  }
  if (!isRecord(entry) || !Array.isArray(entry.status)) {
    return undefined;
  }
  const status = entry.status;
  if (status.length === 0 || !status.every((s): s is string => typeof s === "string" && STATUSES.has(s))) {
    return undefined;
  }
  return status;
}

/** Classifies a parsed webhook body: publish when PUBLISH is in old or new status, draft when in neither, unknown otherwise. */
export function classify(payload: unknown): RouteInput {
  if (!isRecord(payload)) {
    return { api: undefined, id: undefined, decision: "unknown" };
  }
  const api = typeof payload.api === "string" ? payload.api : undefined;
  const id = typeof payload.id === "string" ? payload.id : undefined;
  const contents = payload.contents;
  if (!isRecord(contents) || !("old" in contents) || !("new" in contents)) {
    return { api, id, decision: "unknown" };
  }
  const oldStatus = readStatus(contents.old);
  const newStatus = readStatus(contents.new);
  if (oldStatus === undefined || newStatus === undefined || (oldStatus === null && newStatus === null)) {
    return { api, id, decision: "unknown" };
  }
  const published = [...(oldStatus ?? []), ...(newStatus ?? [])].includes("PUBLISH");
  return { api, id, decision: published ? "publish" : "draft" };
}

function buildReason(parts: (string | undefined)[]): string | undefined {
  const present = parts.filter((part): part is string => part !== undefined);
  if (!present.every((part) => TOKEN_PATTERN.test(part))) {
    return undefined;
  }
  const reason = present.join("-");
  return REASON_PATTERN.test(reason) ? reason : undefined;
}

/**
 * Builds the target and reason. Beta-only (draft) reasons carry the API name and decision only;
 * prod reasons also carry the content ID. Missing api/id are left out. A beta reason with a value
 * outside [A-Za-z0-9_-] or over 64 characters yields ok: false. A prod reason falls back to
 * <api>-<decision>, then <decision>, so prod always yields ok: true.
 */
export function route(input: RouteInput): RouteResult {
  const { api, id, decision } = input;
  if (decision === "draft") {
    const reason = buildReason([api, decision]);
    if (reason === undefined) {
      return { ok: false, decision, api, id };
    }
    return { ok: true, target: "beta", reason, decision, fallback: "none", api, id };
  }
  const candidates: [Fallback, (string | undefined)[]][] = [
    ["none", [api, id, decision]],
    ["without_id", [api, decision]],
    ["decision_only", [decision]],
  ];
  for (const [fallback, parts] of candidates) {
    const reason = buildReason(parts);
    if (reason !== undefined) {
      return { ok: true, target: "prod", reason, decision, fallback, api, id };
    }
  }
  return { ok: false, decision, api, id };
}
