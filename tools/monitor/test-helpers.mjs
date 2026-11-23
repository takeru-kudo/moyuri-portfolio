// Fakes shared by the monitor unit tests. No network access.

export const NOW = Date.parse("2026-11-24T22:00:00Z");

/** Builds a JSON Response. */
export function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

/**
 * Returns a fetch fake. `handler(url, init)` returns a Response (or throws); every call is recorded in
 * `fetchFake.calls` as { url, init }.
 */
export function fakeFetch(handler) {
  const calls = [];
  const fn = async (url, init = {}) => {
    const u = new URL(url);
    calls.push({ url: u, init });
    return handler(u, init);
  };
  fn.calls = calls;
  return fn;
}

/** Builds a check context with fakes. Unset parts throw when used. */
export function makeCtx(overrides = {}) {
  return {
    env: {},
    requireCredentials: false,
    now: () => NOW,
    sleep: async () => {},
    fetch: async () => {
      throw new Error("unexpected fetch");
    },
    resolver: {},
    tlsConnect: async () => {
      throw new Error("unexpected tls");
    },
    readFile: async (p) => {
      throw Object.assign(new Error(`no file ${p}`), { code: "ENOENT" });
    },
    ...overrides,
  };
}

/** readFile fake backed by an object of relative path -> text. */
export function files(map) {
  return async (p) => {
    if (Object.hasOwn(map, p)) return map[p];
    throw Object.assign(new Error(`no file ${p}`), { code: "ENOENT" });
  };
}
