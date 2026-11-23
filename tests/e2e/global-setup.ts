import { setTimeout as delay } from "node:timers/promises";
import { request } from "@playwright/test";
import { accessHeaders, expectedVersion, previewOrigin } from "./src/env.js";

const POLL_INTERVAL_MS = 5_000;
const POLL_TIMEOUT_MS = 2 * 60_000;
const REQUEST_TIMEOUT_MS = 10_000;

/** Waits until the preview serves version.txt with the expected version. */
export default async function globalSetup(): Promise<void> {
  const url = `${previewOrigin()}/version.txt`;
  const expected = expectedVersion();
  const context = await request.newContext({ maxRedirects: 0 });
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  let attempts = 0;
  let lastStatus = "none";
  try {
    while (Date.now() < deadline) {
      attempts += 1;
      try {
        const response = await context.get(url, {
          headers: accessHeaders(),
          maxRedirects: 0,
          timeout: REQUEST_TIMEOUT_MS,
        });
        lastStatus = String(response.status());
        if (response.status() === 200 && (await response.text()).trim() === expected) {
          console.log(`Preview is ready after ${attempts} attempt(s)`);
          return;
        }
        if (response.status() === 200) lastStatus = "200 (version mismatch)";
      } catch {
        lastStatus = "request error";
      }
      await delay(POLL_INTERVAL_MS);
    }
  } finally {
    await context.dispose();
  }
  throw new Error(`Preview not ready after ${attempts} attempt(s); last status: ${lastStatus}`);
}
