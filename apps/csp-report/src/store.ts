// Stores normalised CSP reports in D1 and deletes old rows.

import type { ReportKey } from "./parse.ts";

export const DAILY_NEW_ROW_CAP = 100;
export const RETENTION_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

const UPSERT_SQL = `INSERT INTO violations (directive, blocked_origin, document_path, count, first_seen, last_seen)
SELECT ?1, ?2, ?3, ?4, ?5, ?5
WHERE EXISTS (SELECT 1 FROM violations WHERE directive = ?1 AND blocked_origin = ?2 AND document_path = ?3)
   OR (SELECT COUNT(*) FROM violations WHERE first_seen >= ?6) < ?7
ON CONFLICT (directive, blocked_origin, document_path)
DO UPDATE SET count = count + excluded.count, last_seen = excluded.last_seen`;

const OVERFLOW_SQL = `INSERT INTO overflow (day, count) VALUES (?1, ?2)
ON CONFLICT (day) DO UPDATE SET count = count + excluded.count`;

const DELETE_VIOLATIONS_SQL = "DELETE FROM violations WHERE last_seen < ?1";
const DELETE_OVERFLOW_SQL = "DELETE FROM overflow WHERE day < ?1";

export interface StoreResult {
  stored: number;
  overflow: number;
}

function startOfUtcDay(nowMs: number): number {
  return Math.floor(nowMs / DAY_MS) * DAY_MS;
}

function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * UPSERTs each key with its count. Keys refused by the daily new-row cap, plus `dropped`
 * reports not attempted, add to the UTC day's overflow count.
 */
export async function storeReports(
  db: D1Database,
  entries: [ReportKey, number][],
  dropped: number,
  nowMs: number,
): Promise<StoreResult> {
  const dayStart = startOfUtcDay(nowMs);
  let stored = 0;
  let overflow = dropped;
  for (const [key, count] of entries) {
    const result = await db
      .prepare(UPSERT_SQL)
      .bind(key.directive, key.blockedOrigin, key.documentPath, count, nowMs, dayStart, DAILY_NEW_ROW_CAP)
      .run();
    if (result.meta.changes > 0) {
      stored += count;
    } else {
      overflow += count;
    }
  }
  if (overflow > 0) {
    await db.prepare(OVERFLOW_SQL).bind(utcDay(nowMs), overflow).run();
  }
  return { stored, overflow };
}

export interface CleanupResult {
  violations: number;
  overflow: number;
}

/** Deletes violation rows last seen, and overflow days, older than the retention period. */
export async function deleteOldRows(db: D1Database, nowMs: number): Promise<CleanupResult> {
  const cutoff = nowMs - RETENTION_DAYS * DAY_MS;
  const [violations, overflow] = await db.batch([
    db.prepare(DELETE_VIOLATIONS_SQL).bind(cutoff),
    db.prepare(DELETE_OVERFLOW_SQL).bind(utcDay(cutoff)),
  ]);
  return { violations: violations?.meta.changes ?? 0, overflow: overflow?.meta.changes ?? 0 };
}
