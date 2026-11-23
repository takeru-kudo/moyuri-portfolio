import assert from "node:assert/strict";
import { test } from "node:test";
import { parseIsoDay, stripJsonc, utcDay } from "./lib.mjs";
import { classifyGroup, findings } from "./osv-high.mjs";
import { CHECKS, formatTable, main, runChecks } from "./run.mjs";
import { NOW, makeCtx } from "./test-helpers.mjs";

test("formatTable aligns columns", () => {
  const text = formatTable([
    { name: "a", status: "PASS", detail: "" },
    { name: "longer-name", status: "FAIL", detail: "why" },
  ]);
  assert.equal(text, ["CHECK        RESULT  DETAIL", "a            PASS", "longer-name  FAIL    why"].join("\n"));
});

test("runChecks turns a throwing check into a FAIL and keeps going", async () => {
  const results = await runChecks(makeCtx(), [
    ["boom", { run: async () => { throw Object.assign(new Error("secret"), { code: "EX" }); } }],
    ["ok", { run: async () => [{ name: "ok", status: "PASS", detail: "" }] }],
  ]);
  assert.deepEqual(results, [
    { name: "boom", status: "FAIL", detail: "Error (EX)" },
    { name: "ok", status: "PASS", detail: "" },
  ]);
});

test("main exits 1 on FAIL, 0 on PASS/SKIP only; every check module is wired", async () => {
  assert.equal(CHECKS.length, 12);
  for (const [, mod] of CHECKS) assert.equal(typeof mod.run, "function");
  const lines = [];
  const offline = makeCtx({
    fetch: async () => {
      throw new TypeError("offline", { cause: { code: "ENETUNREACH" } });
    },
  });
  assert.equal(await main(offline, (l) => lines.push(l)), 1);
  assert.match(lines.at(-1), /check\(s\), \d+ failed$/);
});

test("lib: stripJsonc keeps strings intact", () => {
  const text = '{ "u": "https://x//y", /* c */ "s": "a\\"//b", // tail\n "l": [1, 2,], }';
  assert.deepEqual(JSON.parse(stripJsonc(text)), { u: "https://x//y", s: 'a"//b', l: [1, 2] });
});

test("lib: parseIsoDay and utcDay", () => {
  assert.equal(parseIsoDay("2027-11-23").toISOString(), "2027-11-23T00:00:00.000Z");
  assert.equal(parseIsoDay("2027-13-01"), null);
  assert.equal(parseIsoDay(20271123), null);
  assert.equal(utcDay(NOW, -1), "2026-11-23");
});

test("osv-high: classifies groups by score, label, or unknown", () => {
  const vulns = [
    { id: "GHSA-1", database_specific: { severity: "HIGH" } },
    { id: "GHSA-2", database_specific: { severity: "MODERATE" } },
    { id: "MAL-3" },
  ];
  assert.equal(classifyGroup({ ids: ["GHSA-2"], max_severity: "7.5" }, vulns), "high");
  assert.equal(classifyGroup({ ids: ["GHSA-1"], max_severity: "5.0" }, vulns), "low");
  assert.equal(classifyGroup({ ids: ["GHSA-1"], max_severity: "" }, vulns), "high");
  assert.equal(classifyGroup({ ids: ["GHSA-2"] }, vulns), "low");
  assert.equal(classifyGroup({ ids: ["MAL-3"] }, vulns), "unknown");
});

test("osv-high: findings over a report", () => {
  const report = {
    results: [
      {
        packages: [
          {
            package: { ecosystem: "npm", name: "x", version: "1.0.0" },
            vulnerabilities: [{ id: "GHSA-1" }, { id: "GHSA-2" }],
            groups: [{ ids: ["GHSA-1"], max_severity: "9.8" }, { ids: ["GHSA-2"], max_severity: "3.1" }],
          },
        ],
      },
    ],
  };
  assert.deepEqual(findings(report), [{ package: "npm/x@1.0.0", ids: "GHSA-1", level: "high" }]);
  assert.deepEqual(findings({ results: [] }), []);
});
