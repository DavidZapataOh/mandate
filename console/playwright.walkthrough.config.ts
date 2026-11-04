import { defineConfig, devices } from "@playwright/test";

const BASE = process.env.MANDATE_URL;
if (!BASE) throw new Error("walkthrough: set MANDATE_URL to a running mandate-console");

export default defineConfig({
  testDir: "walkthrough",
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  use: { baseURL: BASE, trace: "retain-on-failure" },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } },
    },
  ],
});
