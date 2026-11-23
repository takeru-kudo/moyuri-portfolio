// hooks-relay: verifies microCMS webhooks and dispatches deploy.yml through a GitHub App.

import { readBodyWithLimit } from "./body.ts";
import { dispatchDeploy, GitHubError, isValidConfig } from "./github.ts";
import { classify, route } from "./routing.ts";
import { verifySignature } from "./signature.ts";

export interface Env {
  MICROCMS_WEBHOOK_SECRET: string;
  GITHUB_APP_PRIVATE_KEY: string;
  GITHUB_APP_ID: string;
  GITHUB_INSTALLATION_ID: string;
  GITHUB_OWNER: string;
  GITHUB_REPO: string;
  CF_VERSION_METADATA: WorkerVersionMetadata;
}

const LOG_TOKEN = /^[A-Za-z0-9_-]{1,64}$/;

function json(status: number, body: unknown, extra: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extra },
  });
}

function logToken(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return LOG_TOKEN.test(value) ? value : "(invalid)";
}

function log(fields: Record<string, unknown>): void {
  console.log(JSON.stringify(fields));
}

function healthz(env: Env): Response {
  return json(200, { status: "ok", version: env.CF_VERSION_METADATA.id });
}

async function handleWebhook(request: Request, env: Env): Promise<Response> {
  const body = await readBodyWithLimit(request);
  if (!body.ok) {
    const status = body.reason === "too_large" ? 413 : 400;
    log({ event: "webhook", outcome: body.reason, status });
    return json(status, { error: body.reason });
  }
  const signature = request.headers.get("x-microcms-signature");
  const secret = env.MICROCMS_WEBHOOK_SECRET ?? "";
  const signatureOk = await verifySignature(secret, body.bytes, signature);
  if (!signatureOk) {
    log({
      event: "webhook",
      outcome: "bad_signature",
      status: 401,
      sig_present: signature !== null,
      sig_length: signature?.length ?? 0,
      sig_hex64: signature !== null && /^[0-9a-f]{64}$/i.test(signature),
      secret_length: secret.length,
    });
    return json(401, { error: "unauthorized" });
  }

  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body.bytes));
  } catch {
    payload = undefined;
  }
  const routed = route(classify(payload));
  const api = logToken(routed.api);
  const id = logToken(routed.id);
  if (!routed.ok) {
    log({ event: "webhook", api, id, decision: routed.decision, outcome: "invalid_reason", status: 422 });
    return json(422, { error: "unprocessable" });
  }

  const config = {
    appId: env.GITHUB_APP_ID,
    installationId: env.GITHUB_INSTALLATION_ID,
    owner: env.GITHUB_OWNER,
    repo: env.GITHUB_REPO,
  };
  if (!isValidConfig(config) || typeof env.GITHUB_APP_PRIVATE_KEY !== "string") {
    log({
      event: "webhook",
      api,
      id,
      decision: routed.decision,
      fallback: routed.fallback,
      outcome: "config_invalid",
      status: 500,
    });
    return json(500, { error: "internal" });
  }

  try {
    const githubStatus = await dispatchDeploy(
      { ...config, privateKeyPem: env.GITHUB_APP_PRIVATE_KEY },
      routed.target,
      routed.reason,
      Math.floor(Date.now() / 1000),
    );
    log({
      event: "webhook",
      api,
      id,
      decision: routed.decision,
      target: routed.target,
      fallback: routed.fallback,
      outcome: "dispatched",
      githubStatus,
      status: 202,
    });
    return json(202, { target: routed.target });
  } catch (error) {
    if (!(error instanceof GitHubError)) {
      throw error;
    }
    log({
      event: "webhook",
      api,
      id,
      decision: routed.decision,
      target: routed.target,
      fallback: routed.fallback,
      outcome: "github_failed",
      step: error.step,
      githubStatus: error.status,
      status: 502,
    });
    return json(502, { error: "upstream" });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === "/microcms") {
      if (request.method !== "POST") {
        return json(405, { error: "method_not_allowed" }, { Allow: "POST" });
      }
      try {
        return await handleWebhook(request, env);
      } catch {
        log({ event: "webhook", outcome: "error", status: 500 });
        return json(500, { error: "internal" });
      }
    }
    if (pathname === "/healthz") {
      if (request.method !== "GET") {
        return json(405, { error: "method_not_allowed" }, { Allow: "GET" });
      }
      return healthz(env);
    }
    return json(404, { error: "not_found" });
  },
} satisfies ExportedHandler<Env>;
