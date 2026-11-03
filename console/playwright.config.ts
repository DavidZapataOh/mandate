import { fileURLToPath } from "node:url";
import { defineConfig, devices } from "@playwright/test";

const PORT = 8799;
const BIN = process.env.MANDATE_CONSOLE ?? "../.venv/bin/mandate-console";
const DIST = fileURLToPath(new URL("./dist", import.meta.url));

export default defineConfig({
  testDir: "e2e",
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  use: { baseURL: `http://127.0.0.1:${PORT}`, trace: "retain-on-failure" },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } },
    },
  ],
  webServer: {
    command: `${BIN} --port ${PORT} --console-dir ${DIST}`,
    url: `http://127.0.0.1:${PORT}/console/`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
