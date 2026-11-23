import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig, devices } from "@playwright/test";
import { browserEnv } from "./src/env.js";

export default defineConfig({
  testDir: "./tests",
  globalSetup: "./global-setup.ts",
  timeout: 30_000,
  globalTimeout: 10 * 60_000,
  expect: { timeout: 10_000 },
  forbidOnly: true,
  retries: 0,
  workers: 1,
  fullyParallel: false,
  reporter: [["list"]],
  outputDir: join(process.env.RUNNER_TEMP ?? tmpdir(), "e2e-output"),
  preserveOutput: "never",
  use: {
    trace: "off",
    screenshot: "off",
    video: "off",
    serviceWorkers: "block",
  },
  projects: [
    {
      name: "chrome",
      use: {
        ...devices["Desktop Chrome"],
        channel: "chrome",
        launchOptions: { env: browserEnv() },
      },
    },
  ],
});
