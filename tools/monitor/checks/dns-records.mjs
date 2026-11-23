// CAA, null MX, SPF and DMARC records.

import dns from "node:dns/promises";
import { CAA_CLOUDFLARE_ISSUERS, CAA_ISSUERS, DMARC, SPF, ZONE } from "../config.mjs";
import { describeError, describeValue, fail, pass } from "../lib.mjs";

export const defaultResolver = {
  resolveCaa: (name) => dns.resolveCaa(name),
  resolveMx: (name) => dns.resolveMx(name),
  resolveTxt: (name) => dns.resolveTxt(name),
};

const CAA_TAGS = ["issue", "issuewild"];

/** Returns problems with a CAA record set. */
export function caaProblems(records) {
  const required = new Set(CAA_TAGS.flatMap((tag) => CAA_ISSUERS.map((v) => `${tag} ${v}`)));
  const allowed = new Set([
    ...required,
    ...CAA_TAGS.flatMap((tag) => CAA_CLOUDFLARE_ISSUERS.map((v) => `${tag} ${v}`)),
  ]);
  const seen = new Set();
  const problems = [];
  for (const record of records) {
    const tag = CAA_TAGS.find((t) => typeof record?.[t] === "string");
    if (tag === undefined) {
      problems.push("unexpected CAA tag");
      continue;
    }
    const entry = `${tag} ${record[tag]}`;
    if (record.critical !== 0) problems.push(`CAA ${describeValue(entry)} has critical flag`);
    if (!allowed.has(entry)) problems.push(`unexpected CAA ${describeValue(entry)}`);
    seen.add(entry);
  }
  for (const entry of required) {
    if (!seen.has(entry)) problems.push(`missing CAA ${describeValue(entry)}`);
  }
  return problems;
}

function txtValues(records) {
  return records.map((chunks) => chunks.join(""));
}

async function checkOne(name, fn) {
  try {
    const problems = await fn();
    return problems.length === 0 ? pass(name) : fail(name, problems.join("; "));
  } catch (err) {
    return fail(name, describeError(err));
  }
}

export async function run(ctx) {
  const resolver = ctx.resolver;
  return [
    await checkOne("dns-caa", async () => caaProblems(await resolver.resolveCaa(ZONE))),
    await checkOne("dns-null-mx", async () => {
      const mx = await resolver.resolveMx(ZONE);
      const ok = mx.length === 1 && mx[0].priority === 0 && (mx[0].exchange === "" || mx[0].exchange === ".");
      return ok ? [] : [`MX is not a single null MX (${mx.length} record(s))`];
    }),
    await checkOne("dns-spf", async () => {
      const spf = txtValues(await resolver.resolveTxt(ZONE)).filter((v) => v.toLowerCase().startsWith("v=spf1"));
      return spf.length === 1 && spf[0] === SPF ? [] : [`SPF records: ${spf.map(describeValue).join(", ") || "none"}`];
    }),
    await checkOne("dns-dmarc", async () => {
      const values = txtValues(await resolver.resolveTxt(`_dmarc.${ZONE}`));
      const dmarc = values.filter((v) => v.startsWith("v=DMARC1"));
      return dmarc.length === 1 && dmarc[0] === DMARC ? [] : [`DMARC records: ${dmarc.map(describeValue).join(", ") || "none"}`];
    }),
  ];
}
