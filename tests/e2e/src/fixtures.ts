import { test as base, expect, type APIRequestContext, type APIResponse, type Route } from "@playwright/test";
import { accessHeaders, previewHost, previewOrigin } from "./env.js";

const REQUEST_TIMEOUT_MS = 10_000;

interface PreviewClient {
  /** GETs a path on the preview origin with the Access headers, without following redirects. */
  get(path: string): Promise<APIResponse>;
}

interface PreviewFixtures {
  preview: PreviewClient;
}

/** Returns true when the Location of a redirect points to another host. */
function isOffHostRedirect(status: number, location: string | undefined, base: string): boolean {
  if (status < 300 || status > 399) return false;
  if (location === undefined) return false;
  return new URL(location, base).host !== previewHost();
}

interface RouteCounters {
  offHost: number;
  failed: number;
}

/** Adds the Access headers to a preview request and returns the response without following redirects. */
async function handlePreviewRoute(route: Route, counters: RouteCounters): Promise<void> {
  const request = route.request();
  let response: APIResponse;
  try {
    response = await route.fetch({
      headers: { ...request.headers(), ...accessHeaders() },
      maxRedirects: 0,
      timeout: REQUEST_TIMEOUT_MS,
    });
  } catch {
    counters.failed += 1;
    await route.abort("failed");
    return;
  }
  if (isOffHostRedirect(response.status(), response.headers()["location"], request.url())) {
    counters.offHost += 1;
    await route.abort("blockedbyclient");
    return;
  }
  await route.fulfill({ response });
}

/** GETs a URL with the Access headers; errors are replaced so that request headers are not reported. */
async function getWithAccess(request: APIRequestContext, url: string): Promise<APIResponse> {
  try {
    return await request.get(url, {
      headers: accessHeaders(),
      maxRedirects: 0,
      timeout: REQUEST_TIMEOUT_MS,
    });
  } catch {
    throw new Error("Preview request failed");
  }
}

export const test = base.extend<PreviewFixtures>({
  context: async ({ context }, use) => {
    const host = previewHost();
    const counters: RouteCounters = { offHost: 0, failed: 0 };
    await context.route(
      (url) => url.protocol === "https:" && url.host === host,
      (route) => handlePreviewRoute(route, counters),
    );
    await use(context);
    expect(counters.offHost, "redirects from the preview host to another host").toBe(0);
    expect(counters.failed, "failed preview requests").toBe(0);
  },

  preview: async ({ playwright }, use) => {
    const origin = previewOrigin();
    const request = await playwright.request.newContext({ maxRedirects: 0 });
    await use({
      get: (path) => {
        if (!path.startsWith("/") || path.startsWith("//")) {
          throw new Error("preview.get takes an absolute path");
        }
        return getWithAccess(request, `${origin}${path}`);
      },
    });
    await request.dispose();
  },
});

export { expect };
