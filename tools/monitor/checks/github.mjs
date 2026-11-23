// GitHub repository checks with the monitor token: token expiry, Dependabot alerts, collaborators, `main` ruleset.

import {
  DEPENDABOT_MAX_OPEN_DAYS,
  GITHUB_API,
  GITHUB_OWNER,
  GITHUB_REPO,
  PAT_KEY,
  PAT_MIN_DAYS,
  PAT_RECORD_TOLERANCE_DAYS,
  RULESET,
  RULESET_NAME,
} from "../config.mjs";
import { DAY_MS, daysUntil, describeError, fail, getJson, missingCredential, parseIsoDay, pass } from "../lib.mjs";
import { KEY_EXPIRY_FILE } from "./key-expiry.mjs";

const REPO_PATH = `/repos/${GITHUB_OWNER}/${GITHUB_REPO}`;
const MAX_PAGES = 10;
const NAMES = ["github-token-expiry", "dependabot-alerts", "collaborators", "ruleset-main"];

/** Parses the github-authentication-token-expiration header ("YYYY-MM-DD HH:MM:SS UTC" or "... +0900"). */
export function parseTokenExpiration(value) {
  const match = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (UTC|[+-]\d{4})$/.exec(String(value ?? "").trim());
  if (!match) return null;
  const zone = match[3] === "UTC" ? "Z" : `${match[3].slice(0, 3)}:${match[3].slice(3)}`;
  const date = new Date(`${match[1]}T${match[2]}${zone}`);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Returns the rel="next" URL of a Link header when it stays on the GitHub API origin. */
export function nextLink(link) {
  for (const part of String(link ?? "").split(",")) {
    const match = /^\s*<([^>]+)>\s*;\s*rel="next"\s*$/.exec(part);
    if (!match) continue;
    const url = new URL(match[1]);
    return url.origin === GITHUB_API ? url : null;
  }
  return null;
}

function api(ctx, token, url) {
  return getJson(ctx, url, {
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
    },
  });
}

async function listAll(ctx, token, firstUrl) {
  const items = [];
  let url = new URL(firstUrl);
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const { body, headers } = await api(ctx, token, url);
    if (!Array.isArray(body)) throw new TypeError("expected a list");
    items.push(...body);
    url = nextLink(headers.get("link"));
    if (url === null) return items;
  }
  throw new Error("page limit exceeded");
}

async function tokenExpiry(ctx, token) {
  const name = NAMES[0];
  const { headers } = await api(ctx, token, `${GITHUB_API}${REPO_PATH}`);
  const expires = parseTokenExpiration(headers.get("github-authentication-token-expiration"));
  if (expires === null) return fail(name, "expiration header missing or invalid");
  const days = daysUntil(expires, ctx.now());
  if (days < PAT_MIN_DAYS) return fail(name, `${days} day(s) left`);
  let recorded = null;
  try {
    recorded = parseIsoDay(JSON.parse(await ctx.readFile(KEY_EXPIRY_FILE))?.[PAT_KEY]);
  } catch {
    recorded = null;
  }
  if (recorded === null) return fail(name, `${days} day(s) left; ${PAT_KEY} not recorded in key-expiry.json`);
  if (Math.abs(expires.getTime() - recorded.getTime()) > PAT_RECORD_TOLERANCE_DAYS * DAY_MS) {
    return fail(name, `${days} day(s) left; differs from the ${PAT_KEY} date in key-expiry.json`);
  }
  return pass(name, `${days} day(s) left`);
}

async function dependabot(ctx, token) {
  const name = NAMES[1];
  const url = new URL(`${GITHUB_API}${REPO_PATH}/dependabot/alerts`);
  url.searchParams.set("state", "open");
  url.searchParams.set("severity", "high,critical");
  url.searchParams.set("per_page", "100");
  const alerts = await listAll(ctx, token, url);
  const limit = ctx.now() - DEPENDABOT_MAX_OPEN_DAYS * DAY_MS;
  const stale = alerts.filter((a) => {
    const created = Date.parse(a?.created_at ?? "");
    return Number.isNaN(created) || created <= limit;
  }).length;
  const detail = `${alerts.length} open high/critical, ${stale} open ${DEPENDABOT_MAX_OPEN_DAYS}+ day(s)`;
  return stale === 0 ? pass(name, detail) : fail(name, detail);
}

async function collaborators(ctx, token) {
  const name = NAMES[2];
  const url = new URL(`${GITHUB_API}${REPO_PATH}/collaborators`);
  url.searchParams.set("affiliation", "all");
  url.searchParams.set("per_page", "100");
  const users = await listAll(ctx, token, url);
  const others = users.filter((u) => String(u?.login ?? "").toLowerCase() !== GITHUB_OWNER.toLowerCase()).length;
  const ownerSeen = users.length - others === 1;
  if (others > 0) return fail(name, `${others} collaborator(s) besides the owner`);
  if (!ownerSeen) return fail(name, "owner not listed");
  return pass(name, "owner only");
}

const sorted = (list) => (Array.isArray(list) ? [...list].map(String).sort() : null);
const sameList = (a, b) => JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));

/** Returns the names of fields of a ruleset that differ from RULESET. */
export function rulesetProblems(rs) {
  const problems = [];
  if (rs?.target !== RULESET.target) problems.push("target");
  if (rs?.enforcement !== RULESET.enforcement) problems.push("enforcement");
  if (!sameList(rs?.conditions?.ref_name?.include, RULESET.include)) problems.push("conditions.include");
  if (!sameList(rs?.conditions?.ref_name?.exclude, RULESET.exclude)) problems.push("conditions.exclude");
  if (rs?.bypass_actors !== undefined && !(Array.isArray(rs.bypass_actors) && rs.bypass_actors.length === 0)) {
    problems.push("bypass_actors");
  }
  if (rs?.current_user_can_bypass !== "never") problems.push("current_user_can_bypass");
  const rules = Array.isArray(rs?.rules) ? rs.rules : [];
  const types = rules.map((r) => r?.type);
  if (new Set(types).size !== types.length || !sameList(types, RULESET.ruleTypes)) problems.push("rule types");

  const pr = rules.find((r) => r?.type === "pull_request")?.parameters ?? {};
  for (const [key, want] of Object.entries(RULESET.pullRequest)) {
    const ok = Array.isArray(want) ? sameList(pr[key], want) : pr[key] === want;
    if (!ok) problems.push(`pull_request.${key}`);
  }
  if (Array.isArray(pr.required_reviewers) && pr.required_reviewers.length > 0) {
    problems.push("pull_request.required_reviewers");
  }

  const sc = rules.find((r) => r?.type === "required_status_checks")?.parameters ?? {};
  const want = RULESET.statusChecks;
  if (sc.strict_required_status_checks_policy !== want.strict_required_status_checks_policy) {
    problems.push("required_status_checks.strict");
  }
  if (sc.do_not_enforce_on_create === true) problems.push("required_status_checks.do_not_enforce_on_create");
  const checks = Array.isArray(sc.required_status_checks) ? sc.required_status_checks : [];
  if (!sameList(checks.map((c) => c?.context), want.contexts)) problems.push("required_status_checks.contexts");
  if (checks.some((c) => c?.integration_id !== want.integration_id)) {
    problems.push("required_status_checks.integration_id");
  }
  return problems;
}

async function ruleset(ctx, token) {
  const name = NAMES[3];
  const url = new URL(`${GITHUB_API}${REPO_PATH}/rulesets`);
  url.searchParams.set("per_page", "100");
  const list = await listAll(ctx, token, url);
  const matches = list.filter((r) => r?.name === RULESET_NAME);
  if (matches.length === 0) return fail(name, `ruleset ${RULESET_NAME} not found`);
  if (matches.length > 1) return fail(name, `${matches.length} rulesets named ${RULESET_NAME}`);
  const id = matches[0].id;
  if (!Number.isInteger(id)) return fail(name, "ruleset id is not an integer");
  const { body } = await api(ctx, token, `${GITHUB_API}${REPO_PATH}/rulesets/${id}`);
  const problems = rulesetProblems(body);
  if (problems.length > 0) return fail(name, `differs: ${problems.join(", ")}`);
  return pass(name, body?.bypass_actors === undefined ? "bypass_actors not visible to the token" : "");
}

export async function run(ctx) {
  const token = ctx.env.MONITOR_GITHUB_TOKEN ?? "";
  if (token === "") return NAMES.map((n) => missingCredential(ctx, n, "MONITOR_GITHUB_TOKEN"));
  const checks = [tokenExpiry, dependabot, collaborators, ruleset];
  const results = [];
  for (const [i, check] of checks.entries()) {
    try {
      results.push(await check(ctx, token));
    } catch (err) {
      results.push(fail(NAMES[i], describeError(err)));
    }
  }
  return results;
}
