import AxeBuilder from "@axe-core/playwright";
import { request } from "@playwright/test";
import { CSP_HEADER, GLOBAL_HEADERS, PATH_HEADERS, diffCsp } from "@portfolio/security-headers";
import { expect, test } from "../src/fixtures.js";
import { expectedVersion, previewHost, previewOrigin } from "../src/env.js";

const ACCESS_LOGIN_HOST_SUFFIX = ".cloudflareaccess.com";
const ACCESS_LOGIN_PATH_PREFIX = "/cdn-cgi/access/login/";
const EXPECTED_HEADING = "Moyuri Kudo";

test("request without the service token is redirected to Access login", async () => {
  const context = await request.newContext({ maxRedirects: 0 });
  try {
    const response = await context.get(`${previewOrigin()}/`, { maxRedirects: 0 });
    expect(response.status(), "status").toBe(302);
    const location = new URL(response.headers()["location"] ?? "", previewOrigin());
    expect(location.protocol, "Location protocol").toBe("https:");
    expect(location.host.endsWith(ACCESS_LOGIN_HOST_SUFFIX), "Location is the Access team domain").toBe(true);
    expect(location.pathname.startsWith(ACCESS_LOGIN_PATH_PREFIX), "Location is the Access login path").toBe(true);
  } finally {
    await context.dispose();
  }
});

test("request with the service token is served", async ({ preview }) => {
  const response = await preview.get("/");
  expect(response.status(), "status").toBe(200);
});

test("version marker matches this run", async ({ preview }) => {
  const response = await preview.get("/version.txt");
  expect(response.status(), "status").toBe(200);
  const matches = (await response.text()).trim() === expectedVersion();
  expect(matches, "version.txt matches the expected version").toBe(true);
});

test("security headers match the definition", async ({ preview }) => {
  const response = await preview.get("/");
  expect(response.status(), "status").toBe(200);
  const headers = response.headers();
  for (const [name, value] of GLOBAL_HEADERS) {
    if (name === "X-Robots-Tag") continue;
    expect(headers[name.toLowerCase()], name).toBe(value);
  }
  const robots = (headers["x-robots-tag"] ?? "").split(",").map((token) => token.trim());
  expect(robots, "X-Robots-Tag").toContain("noindex");
  const csp = headers[CSP_HEADER.toLowerCase()];
  expect(csp, CSP_HEADER).toBeDefined();
  expect(diffCsp(csp ?? ""), "CSP differences from the definition").toEqual([]);
  expect(headers["content-security-policy"], "enforcing CSP").toBeUndefined();
});

test("version marker is not cached", async ({ preview }) => {
  const response = await preview.get("/version.txt");
  expect(response.status(), "status").toBe(200);
  const expected = PATH_HEADERS.find(([path]) => path === "/version.txt")?.[1] ?? [];
  expect(expected.length, "headers defined for /version.txt").toBeGreaterThan(0);
  for (const [name, value] of expected) {
    expect(response.headers()[name.toLowerCase()], name).toBe(value);
  }
});

test("security.txt is served", async ({ preview }) => {
  const response = await preview.get("/.well-known/security.txt");
  expect(response.status(), "status").toBe(200);
  const lines = (await response.text()).split("\n");
  expect(lines, "Contact").toContain(
    "Contact: https://github.com/takeru-kudo/moyuri-portfolio/security/advisories/new",
  );
  expect(lines.some((line) => line.startsWith("Expires: ")), "Expires").toBe(true);
});

test.describe("top page", () => {
  test.beforeEach(async ({ page }) => {
    const response = await page.goto(`${previewOrigin()}/`);
    expect(response?.status(), "status").toBe(200);
    expect(new URL(page.url()).host === previewHost(), "page is on the preview host").toBe(true);
  });

  test("shows the heading", async ({ page }) => {
    const headings = await page.locator("h1").allTextContents();
    expect(headings.length, "h1 count").toBe(1);
    expect(headings[0]?.trim() === EXPECTED_HEADING, "h1 matches the expected heading").toBe(true);
  });

  test("has no axe violations", async ({ page }) => {
    const results = await new AxeBuilder({ page }).analyze();
    const ruleIds = results.violations.map((violation) => violation.id).sort();
    expect(ruleIds, "axe violation rule IDs").toEqual([]);
  });
});
