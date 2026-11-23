// DNSSEC: a validating DNS-over-HTTPS resolver sets AD on the zone and a DS record exists.

import { DOH_URL, ZONE } from "../config.mjs";
import { describeError, fail, getJson, pass } from "../lib.mjs";

const TYPE_DS = 43;

async function query(ctx, type) {
  const url = new URL(DOH_URL);
  url.searchParams.set("name", ZONE);
  url.searchParams.set("type", type);
  const { body } = await getJson(ctx, url, { headers: { accept: "application/dns-json" } });
  return body;
}

export async function run(ctx) {
  try {
    const soa = await query(ctx, "SOA");
    const ds = await query(ctx, "DS");
    const problems = [];
    if (soa?.Status !== 0 || soa?.AD !== true) problems.push("SOA answer not authenticated");
    const dsRecords = Array.isArray(ds?.Answer) ? ds.Answer.filter((a) => a?.type === TYPE_DS) : [];
    if (ds?.Status !== 0 || ds?.AD !== true) problems.push("DS answer not authenticated");
    if (dsRecords.length === 0) problems.push("no DS record");
    return [problems.length === 0 ? pass("dnssec", `${dsRecords.length} DS record(s)`) : fail("dnssec", problems.join("; "))];
  } catch (err) {
    return [fail("dnssec", describeError(err))];
  }
}
