// Recorded key expiry / rotation dates in key-expiry.json.

import { KEYS, KEY_MIN_DAYS } from "../config.mjs";
import { daysUntil, describeError, describeValue, fail, parseIsoDay, pass } from "../lib.mjs";

export const KEY_EXPIRY_FILE = "tools/monitor/key-expiry.json";

/** Returns problems for the parsed key-expiry object. */
export function keyProblems(record, now) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) return ["not a JSON object"];
  const problems = [];
  for (const key of KEYS) {
    if (!Object.hasOwn(record, key)) {
      problems.push(`${key} missing`);
      continue;
    }
    const date = parseIsoDay(record[key]);
    if (date === null) {
      problems.push(`${key} has invalid date ${describeValue(record[key])}`);
      continue;
    }
    const days = daysUntil(date, now);
    if (days < KEY_MIN_DAYS) problems.push(`${key} ${days} day(s) left`);
  }
  for (const key of Object.keys(record)) {
    if (!KEYS.includes(key)) problems.push(`unknown key ${describeValue(key)}`);
  }
  return problems;
}

export async function run(ctx) {
  try {
    const record = JSON.parse(await ctx.readFile(KEY_EXPIRY_FILE));
    const problems = keyProblems(record, ctx.now());
    return [problems.length === 0 ? pass("key-expiry", `${KEYS.length} key(s)`) : fail("key-expiry", problems.join("; "))];
  } catch (err) {
    return [fail("key-expiry", describeError(err))];
  }
}
