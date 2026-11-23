// security.txt Expires field.

import { SECURITY_TXT_MIN_DAYS, SECURITY_TXT_URL } from "../config.mjs";
import { daysUntil, describeError, fail, pass, request } from "../lib.mjs";

/** Returns the Expires date of a security.txt body, or null when missing, repeated or invalid. */
export function parseExpires(body) {
  const values = body
    .split(/\r?\n/)
    .map((line) => /^expires:\s*(.+)$/i.exec(line.trim()))
    .filter((m) => m !== null)
    .map((m) => m[1].trim());
  if (values.length !== 1) return null;
  const date = new Date(values[0]);
  return Number.isNaN(date.getTime()) ? null : date;
}

export async function run(ctx) {
  try {
    const res = await request(ctx, SECURITY_TXT_URL, { method: "GET" });
    if (res.status !== 200) {
      await res.body?.cancel?.();
      return [fail("security-txt", `status ${res.status}`)];
    }
    const expires = parseExpires(await res.text());
    if (expires === null) return [fail("security-txt", "Expires missing or invalid")];
    const days = daysUntil(expires, ctx.now());
    return [days < SECURITY_TXT_MIN_DAYS ? fail("security-txt", `${days} day(s) left`) : pass("security-txt", `${days} day(s) left`)];
  } catch (err) {
    return [fail("security-txt", describeError(err))];
  }
}
