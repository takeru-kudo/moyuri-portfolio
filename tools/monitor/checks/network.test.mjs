// Tests for the checks that only read public endpoints: TLS, RDAP, DNSSEC, DNS records, CT, workers.dev,
// security.txt and Node.js end of life.

import assert from "node:assert/strict";
import { test } from "node:test";
import { CAA_CLOUDFLARE_ISSUERS, CAA_ISSUERS, DMARC, SPF, TLS_HOSTS, WORKERS } from "../config.mjs";
import { DAY_MS } from "../lib.mjs";
import { NOW, fakeFetch, files, json, makeCtx } from "../test-helpers.mjs";
import * as ct from "./ct.mjs";
import { caaProblems, run as runDns } from "./dns-records.mjs";
import { run as runDnssec } from "./dnssec.mjs";
import { nodeMajor, run as runNodeEol } from "./node-eol.mjs";
import { run as runRdap } from "./rdap.mjs";
import { parseExpires, run as runSecurityTxt } from "./security-txt.mjs";
import { run as runTls } from "./tls.mjs";
import { run as runWorkersDev } from "./workers-dev.mjs";

const days = (n) => new Date(NOW + n * DAY_MS);
const statuses = (results) => results.map((r) => r.status);

test("tls: fails under 14 days and on connection errors", async () => {
  const tlsConnect = async (host) => {
    if (host === TLS_HOSTS[1]) return { validTo: days(13.5) };
    if (host === TLS_HOSTS[2]) throw Object.assign(new Error("x"), { code: "CERT_HAS_EXPIRED" });
    return { validTo: days(80) };
  };
  const results = await runTls(makeCtx({ tlsConnect }));
  assert.deepEqual(statuses(results), TLS_HOSTS.map((_, i) => (i === 1 || i === 2 ? "FAIL" : "PASS")));
  assert.equal(results[1].detail, "13 day(s) left");
  assert.equal(results[2].detail, "Error (CERT_HAS_EXPIRED)");
});

function rdapBody({ expires = days(300).toISOString(), status = ["client transfer prohibited"] } = {}) {
  return { events: [{ eventAction: "registration", eventDate: "2026-11-07T10:20:46Z" }, { eventAction: "expiration", eventDate: expires }], status };
}

test("rdap: pass, near expiry, unlocked, missing event, HTTP error", async () => {
  const runWith = (body, status = 200) => runRdap(makeCtx({ fetch: fakeFetch(() => json(body, status)) }));
  assert.deepEqual(statuses(await runWith(rdapBody())), ["PASS", "PASS"]);
  assert.deepEqual(statuses(await runWith(rdapBody({ expires: days(59).toISOString() }))), ["FAIL", "PASS"]);
  assert.deepEqual(statuses(await runWith(rdapBody({ status: ["active"] }))), ["PASS", "FAIL"]);
  assert.deepEqual(statuses(await runWith({ events: [], status: [] })), ["FAIL", "FAIL"]);
  const errored = await runWith({}, 503);
  assert.deepEqual(statuses(errored), ["FAIL", "FAIL"]);
  assert.equal(errored[0].detail, "HttpError (status 503)");
});

test("dnssec: needs AD on both answers and a DS record", async () => {
  const runWith = (soa, ds) =>
    runDnssec(makeCtx({ fetch: fakeFetch((url) => json(url.searchParams.get("type") === "DS" ? ds : soa)) }));
  const good = { Status: 0, AD: true, Answer: [{ type: 43, data: "2371 13 2 ABC" }] };
  assert.equal((await runWith({ Status: 0, AD: true }, good))[0].status, "PASS");
  assert.equal((await runWith({ Status: 0, AD: false }, good))[0].status, "FAIL");
  assert.equal((await runWith({ Status: 0, AD: true }, { Status: 0, AD: true, Answer: [] }))[0].status, "FAIL");
  assert.equal((await runWith({ Status: 2, AD: false }, good))[0].status, "FAIL");
});

const caa = (tag, value) => ({ critical: 0, type: "CAA", [tag]: value });
const goodCaa = () =>
  ["issue", "issuewild"].flatMap((tag) => [...CAA_ISSUERS, ...CAA_CLOUDFLARE_ISSUERS].map((v) => caa(tag, v)));

test("caaProblems: required issuers, Cloudflare extras allowed, others rejected", () => {
  assert.deepEqual(caaProblems(goodCaa()), []);
  assert.deepEqual(caaProblems(goodCaa().filter((r) => !CAA_CLOUDFLARE_ISSUERS.includes(r.issue ?? r.issuewild))), []);
  assert.deepEqual(caaProblems(goodCaa().filter((r) => r.issuewild !== "ssl.com")), ['missing CAA "issuewild ssl.com"']);
  assert.deepEqual(caaProblems([...goodCaa(), caa("issue", "evil-ca.example")]), ['unexpected CAA "issue evil-ca.example"']);
  assert.deepEqual(caaProblems([...goodCaa(), { critical: 0, iodef: "mailto:x@example.com" }]), ["unexpected CAA tag"]);
  assert.deepEqual(caaProblems([{ ...caa("issue", "ssl.com"), critical: 128 }, ...goodCaa()]), ['CAA "issue ssl.com" has critical flag']);
});

function resolver({ mx = [{ exchange: "", priority: 0 }], txt = [[SPF]], dmarc = [[DMARC]], caaRecords = goodCaa() } = {}) {
  return {
    resolveCaa: async () => caaRecords,
    resolveMx: async () => mx,
    resolveTxt: async (name) => (name.startsWith("_dmarc.") ? dmarc : txt),
  };
}

test("dns records: pass and each failure", async () => {
  const runWith = (opts) => runDns(makeCtx({ resolver: resolver(opts) }));
  assert.deepEqual(statuses(await runWith()), ["PASS", "PASS", "PASS", "PASS"]);
  assert.deepEqual(statuses(await runWith({ mx: [{ exchange: "mail.example", priority: 10 }] })), ["PASS", "FAIL", "PASS", "PASS"]);
  assert.deepEqual(statuses(await runWith({ txt: [["v=spf1 ", "include:x -all"]] })), ["PASS", "PASS", "FAIL", "PASS"]);
  assert.deepEqual(statuses(await runWith({ txt: [[SPF], [SPF]] })), ["PASS", "PASS", "FAIL", "PASS"]);
  assert.deepEqual(statuses(await runWith({ dmarc: [["v=DMARC1; p=none"]] })), ["PASS", "PASS", "PASS", "FAIL"]);
  const nodata = { resolveCaa: async () => { throw Object.assign(new Error("x"), { code: "ENODATA" }); } };
  const [caaResult] = await runDns(makeCtx({ resolver: { ...resolver(), ...nodata } }));
  assert.equal(caaResult.detail, "Error (ENODATA)");
});

test("ct: issuerOrg", () => {
  assert.equal(ct.issuerOrg("C=US, O=Let's Encrypt, CN=E7"), "Let's Encrypt");
  assert.equal(ct.issuerOrg('C=GB, O="Sectigo Limited", CN=x'), "Sectigo Limited");
  assert.equal(ct.issuerOrg("CN=nothing"), null);
});

const crtEntry = (id, issuer, names, notAfter = "2027-02-05T09:24:21") => ({ id, issuer_name: issuer, name_value: names, not_after: notAfter });

test("ct: crt.sh pass, unexpected issuer and host, expired entries ignored", async () => {
  const runWith = (entries) => ct.run(makeCtx({ fetch: fakeFetch(() => json(entries)) }));
  const good = [crtEntry(1, "C=US, O=Let's Encrypt, CN=YE2", "*.moyuri-kudo.com\nmoyuri-kudo.com")];
  const [ok] = await runWith(good);
  assert.equal(ok.status, "PASS");
  assert.equal(ok.detail, "1 unexpired certificate(s) via crt.sh");

  const [bad] = await runWith([...good, crtEntry(2, "C=XX, O=Evil CA, CN=1", "admin.moyuri-kudo.com")]);
  assert.equal(bad.status, "FAIL");
  assert.match(bad.detail, /unexpected issuer "Evil CA"/);
  assert.match(bad.detail, /unexpected host "admin.moyuri-kudo.com"/);

  const [old] = await runWith([...good, crtEntry(3, "C=XX, O=Evil CA, CN=1", "x.moyuri-kudo.com", "2026-01-01T00:00:00")]);
  assert.equal(old.status, "PASS");
});

test("ct: queries apex and subdomains, merges duplicates by id", async () => {
  const fetch = fakeFetch(() => json([crtEntry(1, "C=US, O=Google Trust Services, CN=WR1", "moyuri-kudo.com")]));
  const [result] = await ct.run(makeCtx({ fetch }));
  assert.deepEqual(fetch.calls.map((c) => c.url.searchParams.get("q")), ["moyuri-kudo.com", "%.moyuri-kudo.com"]);
  assert.equal(result.detail, "1 unexpired certificate(s) via crt.sh");
});

test("ct: falls back to Cert Spotter after crt.sh retries, and paginates", async () => {
  const fetch = fakeFetch((url) => {
    if (url.hostname === "crt.sh") return new Response("bad gateway", { status: 502 });
    if (url.searchParams.get("after") === "7") return json([]);
    return json([{ id: "7", dns_names: ["beta.moyuri-kudo.com"], issuer: { name: "C=US, O=SSL Corporation, CN=x" }, not_after: "2027-02-05T10:20:49Z" }]);
  });
  const [result] = await ct.run(makeCtx({ fetch }));
  assert.equal(result.status, "PASS");
  assert.equal(result.detail, "1 unexpired certificate(s) via certspotter");
  assert.equal(fetch.calls.filter((c) => c.url.hostname === "crt.sh").length, 3);
  assert.deepEqual(fetch.calls.filter((c) => c.url.hostname !== "crt.sh").length, 2);
});

test("ct: fails when both sources fail", async () => {
  const fetch = fakeFetch(() => new Response("", { status: 503 }));
  const [result] = await ct.run(makeCtx({ fetch }));
  assert.equal(result.status, "FAIL");
  assert.equal(result.detail, "crt.sh: HttpError (status 503); Cert Spotter: HttpError (status 503)");
});

test("ct: zero certificates from crt.sh fall through to Cert Spotter; zero from both fails", async () => {
  const fetch = fakeFetch((url) => {
    if (url.hostname === "crt.sh") return json([]);
    if (url.searchParams.has("after")) return json([]);
    return json([{ id: "1", dns_names: ["moyuri-kudo.com"], issuer: { name: "C=US, O=Let's Encrypt, CN=E7" }, not_after: "2027-02-05T10:20:49Z" }]);
  });
  const [viaFallback] = await ct.run(makeCtx({ fetch }));
  assert.equal(viaFallback.detail, "1 unexpired certificate(s) via certspotter");
  const [empty] = await ct.run(makeCtx({ fetch: fakeFetch(() => json([])) }));
  assert.equal(empty.status, "FAIL");
  assert.match(empty.detail, /no unexpired certificate/);
});

const ACCOUNT = "0123456789abcdef0123456789abcdef";
const cfEnv = { CLOUDFLARE_API_TOKEN: "cf-token", CLOUDFLARE_ACCOUNT_ID: ACCOUNT };

function workersFetch({ subdomain = "acct", enabled = {}, missing = [], probe = () => new Response("", { status: 404 }) } = {}) {
  return fakeFetch((url) => {
    if (url.hostname === "api.cloudflare.com") {
      if (url.pathname.endsWith("/workers/subdomain")) return json({ success: true, result: { subdomain } });
      const worker = url.pathname.split("/").at(-2);
      if (missing.includes(worker)) return json({ success: false }, 404);
      return json({ success: true, result: { enabled: enabled[worker] ?? false, previews_enabled: true } });
    }
    return probe(url);
  });
}

test("workers-dev: credentials and account validation", async () => {
  assert.equal((await runWorkersDev(makeCtx()))[0].status, "SKIP");
  assert.equal((await runWorkersDev(makeCtx({ requireCredentials: true })))[0].status, "FAIL");
  const bad = { ...cfEnv, CLOUDFLARE_ACCOUNT_ID: "../x" };
  assert.equal((await runWorkersDev(makeCtx({ env: bad })))[0].status, "FAIL");
});

test("workers-dev: pass when disabled and URLs do not serve; probes the API subdomain", async () => {
  const fetch = workersFetch({ missing: ["csp-report"] });
  const [ok] = await runWorkersDev(makeCtx({ env: cfEnv, fetch }));
  assert.deepEqual([ok.status, ok.detail], ["PASS", "3 of 4 Worker(s) exist, all disabled"]);
  assert.deepEqual(
    fetch.calls.filter((c) => c.url.hostname.endsWith(".workers.dev")).map((c) => c.url.href),
    WORKERS.map(([w, p]) => `https://${w}.acct.workers.dev${p}`),
  );
  assert.ok(fetch.calls.filter((c) => c.url.hostname === "api.cloudflare.com").every((c) => c.init.headers.authorization === "Bearer cf-token"));
  assert.ok(!ok.detail.includes("cf-token"));
});

test("workers-dev: fails on an enabled setting, a 2xx/3xx answer, a timeout, a bad subdomain", async () => {
  const [enabled] = await runWorkersDev(makeCtx({ env: cfEnv, fetch: workersFetch({ enabled: { "site-beta": true } }) }));
  assert.equal(enabled.status, "FAIL");
  assert.match(enabled.detail, /site-beta enabled/);

  for (const status of [200, 302]) {
    const probe = (url) => new Response("", { status: url.hostname.startsWith("hooks-relay.") ? status : 404 });
    const [served] = await runWorkersDev(makeCtx({ env: cfEnv, fetch: workersFetch({ probe }) }));
    assert.equal(served.status, "FAIL");
    assert.match(served.detail, new RegExp(`hooks-relay URL status ${status}`));
  }

  const refused = () => {
    throw new TypeError("fetch failed", { cause: { code: "ECONNREFUSED" } });
  };
  assert.equal((await runWorkersDev(makeCtx({ env: cfEnv, fetch: workersFetch({ probe: refused }) })))[0].status, "PASS");

  const timeout = () => {
    throw new DOMException("timed out", "TimeoutError");
  };
  assert.equal((await runWorkersDev(makeCtx({ env: cfEnv, fetch: workersFetch({ probe: timeout }) })))[0].status, "FAIL");

  const [badSub] = await runWorkersDev(makeCtx({ env: cfEnv, fetch: workersFetch({ subdomain: "a.b" }) }));
  assert.equal(badSub.status, "FAIL");

  const [absent] = await runWorkersDev(makeCtx({ env: cfEnv, fetch: workersFetch({ missing: ["site-prod"] }) }));
  assert.equal(absent.status, "FAIL");
  assert.match(absent.detail, /site-prod not found/);

  const [denied] = await runWorkersDev(makeCtx({ env: cfEnv, fetch: fakeFetch(() => json({}, 403)) }));
  assert.equal(denied.detail, "HttpError (status 403)");
});

test("security.txt: parseExpires", () => {
  assert.equal(parseExpires("Contact: x\nExpires: 2027-11-23T00:00:00.000Z\n").toISOString(), "2027-11-23T00:00:00.000Z");
  assert.equal(parseExpires("Contact: x\n"), null);
  assert.equal(parseExpires("Expires: 2027-11-23T00:00:00Z\nExpires: 2028-01-01T00:00:00Z"), null);
  assert.equal(parseExpires("Expires: soon"), null);
});

test("security.txt: pass, near expiry, 404", async () => {
  const runWith = (res) => runSecurityTxt(makeCtx({ fetch: fakeFetch(() => res) }));
  assert.equal((await runWith(new Response(`Expires: ${days(40).toISOString()}\n`)))[0].status, "PASS");
  assert.equal((await runWith(new Response(`Expires: ${days(29).toISOString()}\n`)))[0].status, "FAIL");
  const [missing] = await runWith(new Response("", { status: 404 }));
  assert.deepEqual([missing.status, missing.detail], ["FAIL", "status 404"]);
});

test("node-eol: nodeMajor", () => {
  assert.equal(nodeMajor('[tools]\nnode = "26.13.0"\npnpm = "12.17.0"\n'), "26");
  assert.equal(nodeMajor("[tools]\n"), null);
});

test("node-eol: queries the pinned major and compares the date", async () => {
  const mise = { ".mise.toml": '[tools]\nnode = "26.13.0"\n' };
  const runWith = (eolFrom) => {
    const fetch = fakeFetch(() => json({ result: { name: "26", eolFrom } }));
    return { fetch, done: runNodeEol(makeCtx({ fetch, readFile: files(mise) })) };
  };
  const ok = runWith("2029-04-30");
  assert.equal((await ok.done)[0].status, "PASS");
  assert.equal(ok.fetch.calls[0].url.href, "https://endoflife.date/api/v1/products/nodejs/releases/26");
  assert.equal((await runWith(days(89).toISOString().slice(0, 10)).done)[0].status, "FAIL");
  assert.equal((await runWith(null).done)[0].status, "FAIL");
});
