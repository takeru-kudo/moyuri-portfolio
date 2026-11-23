// Runs every daily monitor check, prints a PASS/FAIL/SKIP table and exits non-zero on any FAIL.
// Environment: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, MONITOR_GITHUB_TOKEN (all optional;
// missing ones SKIP their checks), MONITOR_REQUIRE_CREDENTIALS=1 turns those SKIPs into FAILs.

import { readFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import * as cspD1 from "./checks/csp-d1.mjs";
import * as ct from "./checks/ct.mjs";
import * as dnsRecords from "./checks/dns-records.mjs";
import * as dnssec from "./checks/dnssec.mjs";
import * as github from "./checks/github.mjs";
import * as headers from "./checks/headers.mjs";
import * as keyExpiry from "./checks/key-expiry.mjs";
import * as nodeEol from "./checks/node-eol.mjs";
import * as rdap from "./checks/rdap.mjs";
import * as securityTxt from "./checks/security-txt.mjs";
import * as tls from "./checks/tls.mjs";
import * as workersDev from "./checks/workers-dev.mjs";
import { FAIL, describeError, fail } from "./lib.mjs";

export const CHECKS = [
  ["headers", headers],
  ["tls", tls],
  ["rdap", rdap],
  ["dnssec", dnssec],
  ["dns-records", dnsRecords],
  ["ct", ct],
  ["workers-dev", workersDev],
  ["security-txt", securityTxt],
  ["csp-d1", cspD1],
  ["key-expiry", keyExpiry],
  ["github", github],
  ["node-eol", nodeEol],
];

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

/** Builds the default context with real network, DNS, TLS and file access. */
export function defaultContext(env = process.env) {
  return {
    env,
    requireCredentials: env.MONITOR_REQUIRE_CREDENTIALS === "1",
    fetch: globalThis.fetch,
    now: Date.now,
    sleep: (ms) => delay(ms),
    resolver: dnsRecords.defaultResolver,
    tlsConnect: (host) => tls.connectTls(host),
    readFile: (relative) => readFile(path.join(REPO_ROOT, relative), "utf8"),
  };
}

/** Formats results as an aligned text table. */
export function formatTable(results) {
  const rows = [["CHECK", "RESULT", "DETAIL"], ...results.map((r) => [r.name, r.status, r.detail ?? ""])];
  const width = [0, 1].map((i) => Math.max(...rows.map((row) => row[i].length)));
  return rows.map((row) => `${row[0].padEnd(width[0])}  ${row[1].padEnd(width[1])}  ${row[2]}`.trimEnd()).join("\n");
}

/** Runs all checks and returns the results. A check that throws yields a FAIL. */
export async function runChecks(ctx, checks = CHECKS) {
  const results = [];
  for (const [label, check] of checks) {
    try {
      results.push(...(await check.run(ctx)));
    } catch (err) {
      results.push(fail(label, describeError(err)));
    }
  }
  return results;
}

export async function main(ctx = defaultContext(), log = console.log) {
  const results = await runChecks(ctx);
  log(formatTable(results));
  const failed = results.filter((r) => r.status === FAIL).length;
  log(`\n${results.length} check(s), ${failed} failed`);
  return failed === 0 ? 0 : 1;
}

if (import.meta.main) {
  process.exitCode = await main();
}
