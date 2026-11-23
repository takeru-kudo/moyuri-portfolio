// Certificate Transparency: unexpired certificates for the zone use allowed issuers and host names.
// Source: crt.sh, with Cert Spotter as the fallback when crt.sh does not answer.

import { CRT_SH_URL, CT_HOSTNAMES, CT_ISSUER_ORGS, ZONE } from "../config.mjs";
import { describeError, describeValue, fail, getJson, pass, withRetry } from "../lib.mjs";

export const CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances";
const CRT_SH_ATTEMPTS = 3;
const CRT_SH_RETRY_MS = 10_000;
const CERTSPOTTER_MAX_PAGES = 10;

/** Extracts the O= value from an issuer distinguished name. */
export function issuerOrg(dn) {
  const match = /(?:^|,\s*)O=(?:"([^"]*)"|([^,]*))/.exec(String(dn ?? ""));
  if (!match) return null;
  return (match[1] ?? match[2]).trim();
}

/** Parses a crt.sh timestamp (UTC, without a zone suffix). */
function parseCrtShDate(text) {
  const raw = String(text ?? "");
  return new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(raw) ? raw : `${raw}Z`);
}

async function fromCrtSh(ctx) {
  const certs = new Map();
  for (const q of [ZONE, `%.${ZONE}`]) {
    const url = new URL(CRT_SH_URL);
    url.searchParams.set("q", q);
    url.searchParams.set("output", "json");
    url.searchParams.set("exclude", "expired");
    const { body } = await withRetry(ctx, CRT_SH_ATTEMPTS, CRT_SH_RETRY_MS, () => getJson(ctx, url));
    if (!Array.isArray(body)) throw new TypeError("crt.sh response is not a list");
    for (const entry of body) {
      certs.set(`crtsh-${entry?.id}`, {
        issuer: entry?.issuer_name,
        names: String(entry?.name_value ?? "").split("\n"),
        notAfter: parseCrtShDate(entry?.not_after),
      });
    }
  }
  return [...certs.values()];
}

async function fromCertSpotter(ctx) {
  const certs = [];
  let after = null;
  for (let page = 0; page < CERTSPOTTER_MAX_PAGES; page += 1) {
    const url = new URL(CERTSPOTTER_URL);
    url.searchParams.set("domain", ZONE);
    url.searchParams.set("include_subdomains", "true");
    url.searchParams.append("expand", "dns_names");
    url.searchParams.append("expand", "issuer");
    if (after !== null) url.searchParams.set("after", after);
    const { body } = await getJson(ctx, url);
    if (!Array.isArray(body)) throw new TypeError("Cert Spotter response is not a list");
    if (body.length === 0) return certs;
    for (const entry of body) {
      certs.push({
        issuer: entry?.issuer?.name,
        names: Array.isArray(entry?.dns_names) ? entry.dns_names : [],
        notAfter: new Date(entry?.not_after ?? ""),
      });
    }
    after = String(body.at(-1)?.id ?? "");
    if (after === "") return certs;
  }
  throw new Error("Cert Spotter result exceeds the page limit");
}

/** Returns problems for a list of { issuer, names, notAfter } certificates. */
export function ctProblems(certs, now) {
  const problems = new Set();
  let current = 0;
  for (const cert of certs) {
    if (!(cert.notAfter.getTime() > now)) continue;
    current += 1;
    const org = issuerOrg(cert.issuer);
    if (org === null || !CT_ISSUER_ORGS.includes(org)) problems.add(`unexpected issuer ${describeValue(org)}`);
    for (const raw of cert.names) {
      const name = raw.trim().toLowerCase();
      if (name !== "" && !CT_HOSTNAMES.includes(name)) problems.add(`unexpected host ${describeValue(name)}`);
    }
  }
  return { current, problems: [...problems] };
}

export async function run(ctx) {
  let crtError = "no unexpired certificate";
  try {
    const result = ctProblems(await fromCrtSh(ctx), ctx.now());
    if (result.current > 0) return [report(result, "crt.sh")];
  } catch (err) {
    crtError = describeError(err);
  }
  try {
    const result = ctProblems(await fromCertSpotter(ctx), ctx.now());
    if (result.current > 0) return [report(result, "certspotter")];
    return [fail("ct-log", `crt.sh: ${crtError}; Cert Spotter: no unexpired certificate`)];
  } catch (err) {
    return [fail("ct-log", `crt.sh: ${crtError}; Cert Spotter: ${describeError(err)}`)];
  }
}

function report({ current, problems }, source) {
  const summary = `${current} unexpired certificate(s) via ${source}`;
  return problems.length === 0 ? pass("ct-log", summary) : fail("ct-log", `${summary}; ${problems.join("; ")}`);
}
