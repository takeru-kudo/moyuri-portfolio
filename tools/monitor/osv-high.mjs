// Reads OSV-Scanner JSON output and exits non-zero when a vulnerability group is High or above
// (CVSS max_severity >= 7.0, or database severity HIGH/CRITICAL) or has no severity at all.
// Usage: node tools/monitor/osv-high.mjs <osv-scanner-output.json>

import { readFile } from "node:fs/promises";

export const HIGH_SCORE = 7.0;
const HIGH_LABELS = new Set(["HIGH", "CRITICAL"]);
const KNOWN_LABELS = new Set(["LOW", "MODERATE", "MEDIUM", ...HIGH_LABELS]);

/** Classifies a vulnerability group as "high", "low" or "unknown". */
export function classifyGroup(group, vulns) {
  const score = Number.parseFloat(group?.max_severity ?? "");
  if (Number.isFinite(score)) return score >= HIGH_SCORE ? "high" : "low";
  const ids = new Set(Array.isArray(group?.ids) ? group.ids : []);
  const labels = vulns
    .filter((v) => ids.has(v?.id))
    .map((v) => String(v?.database_specific?.severity ?? "").toUpperCase())
    .filter((label) => KNOWN_LABELS.has(label));
  if (labels.length === 0) return "unknown";
  return labels.some((label) => HIGH_LABELS.has(label)) ? "high" : "low";
}

/** Returns findings { package, ids, level } for groups that are high or unknown. */
export function findings(report) {
  const out = [];
  for (const result of Array.isArray(report?.results) ? report.results : []) {
    for (const pkg of Array.isArray(result?.packages) ? result.packages : []) {
      const vulns = Array.isArray(pkg?.vulnerabilities) ? pkg.vulnerabilities : [];
      for (const group of Array.isArray(pkg?.groups) ? pkg.groups : []) {
        const level = classifyGroup(group, vulns);
        if (level === "low") continue;
        out.push({
          package: `${pkg?.package?.ecosystem}/${pkg?.package?.name}@${pkg?.package?.version}`,
          ids: Array.isArray(group?.ids) ? group.ids.join(",") : "",
          level,
        });
      }
    }
  }
  return out;
}

export async function main(argv = process.argv.slice(2), log = console.log) {
  if (argv.length !== 1) {
    log("usage: osv-high.mjs <osv-scanner-output.json>");
    return 2;
  }
  const report = JSON.parse(await readFile(argv[0], "utf8"));
  const found = findings(report);
  for (const f of found) log(`${f.level.toUpperCase()} ${f.package} ${f.ids}`);
  log(`${found.length} high or unrated vulnerability group(s)`);
  return found.length === 0 ? 0 : 1;
}

if (import.meta.main) {
  process.exitCode = await main();
}
