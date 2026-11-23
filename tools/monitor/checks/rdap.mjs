// Domain expiry and transfer lock from the registry RDAP record.

import { DOMAIN_MIN_DAYS, RDAP_URL } from "../config.mjs";
import { daysUntil, describeError, fail, getJson, pass } from "../lib.mjs";

export async function run(ctx) {
  let body;
  try {
    ({ body } = await getJson(ctx, RDAP_URL, { headers: { accept: "application/rdap+json" } }));
  } catch (err) {
    const detail = describeError(err);
    return [fail("domain-expiry", detail), fail("domain-transfer-lock", detail)];
  }

  const results = [];
  const events = Array.isArray(body?.events) ? body.events : [];
  const expiration = events.find((e) => e?.eventAction === "expiration");
  const date = new Date(expiration?.eventDate ?? "");
  if (Number.isNaN(date.getTime())) {
    results.push(fail("domain-expiry", "no expiration event"));
  } else {
    const days = daysUntil(date, ctx.now());
    results.push(days < DOMAIN_MIN_DAYS ? fail("domain-expiry", `${days} day(s) left`) : pass("domain-expiry", `${days} day(s) left`));
  }

  const status = Array.isArray(body?.status) ? body.status.map((s) => String(s).toLowerCase()) : [];
  results.push(
    status.includes("client transfer prohibited")
      ? pass("domain-transfer-lock")
      : fail("domain-transfer-lock", "client transfer prohibited not set"),
  );
  return results;
}
