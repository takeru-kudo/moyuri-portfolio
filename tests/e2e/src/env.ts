const PREVIEW_URL_RE = /^https:\/\/[0-9a-f]{8}-site-prod\.[a-z0-9]([a-z0-9-]*[a-z0-9])?\.workers\.dev$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const RUN_ID_RE = /^[0-9]{1,20}$/;
const VERSION_RE = /^[0-9a-f]{40}-[0-9]{1,20}$/;
const ACCESS_ENV_PREFIX = "CF_ACCESS_";

/** Returns the preview origin from PREVIEW_URL, or throws. */
export function previewOrigin(): string {
  const raw = process.env.PREVIEW_URL ?? "";
  if (!PREVIEW_URL_RE.test(raw)) {
    throw new Error("PREVIEW_URL is missing or not a site-prod preview URL");
  }
  return new URL(raw).origin;
}

/** Returns the host of the preview origin. */
export function previewHost(): string {
  return new URL(previewOrigin()).host;
}

/** Returns the Access service token headers, or throws. */
export function accessHeaders(): Record<string, string> {
  const id = process.env.CF_ACCESS_CLIENT_ID ?? "";
  const secret = process.env.CF_ACCESS_CLIENT_SECRET ?? "";
  if (id === "" || secret === "") {
    throw new Error("CF_ACCESS_CLIENT_ID or CF_ACCESS_CLIENT_SECRET is missing");
  }
  return { "CF-Access-Client-Id": id, "CF-Access-Client-Secret": secret };
}

/**
 * Returns the expected version.txt content. In GitHub Actions it is
 * "<GITHUB_SHA>-<GITHUB_RUN_ID>"; elsewhere EXPECTED_VERSION is used.
 */
export function expectedVersion(): string {
  if (process.env.GITHUB_ACTIONS === "true") {
    const sha = process.env.GITHUB_SHA ?? "";
    const runId = process.env.GITHUB_RUN_ID ?? "";
    if (!SHA_RE.test(sha) || !RUN_ID_RE.test(runId)) {
      throw new Error("GITHUB_SHA or GITHUB_RUN_ID is missing or malformed");
    }
    return `${sha}-${runId}`;
  }
  const local = process.env.EXPECTED_VERSION ?? "";
  if (!VERSION_RE.test(local)) {
    throw new Error("EXPECTED_VERSION is missing or not <sha>-<run_id>");
  }
  return local;
}

/** Returns a copy of the process environment without Access credentials. */
export function browserEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined || key.toUpperCase().startsWith(ACCESS_ENV_PREFIX)) continue;
    env[key] = value;
  }
  return env;
}
