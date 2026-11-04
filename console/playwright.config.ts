import { fileURLToPath } from "node:url";
import { defineConfig, devices } from "@playwright/test";

const PORT = 8799;
const INTENT_PORT = 8798;
const BIN = process.env.MANDATE_CONSOLE ?? "../.venv/bin/mandate-console";
const PYTHON = process.env.MANDATE_PYTHON ?? "../.venv/bin/python";
const DIST = fileURLToPath(new URL("./dist", import.meta.url));
const CLIP = fileURLToPath(new URL("../demo/voice/pay-acme.wav", import.meta.url));

export default defineConfig({
  testDir: "e2e",
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  use: { baseURL: `http://127.0.0.1:${PORT}`, trace: "retain-on-failure" },
  projects: [
    {
      name: "chromium",
      testIgnore: /intent\.spec\.ts/,
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } },
    },
    {
      name: "intent",
      testMatch: /intent\.spec\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 900 },
        baseURL: `http://127.0.0.1:${INTENT_PORT}`,
        launchOptions: {
          // The demo clip stands in for the microphone.
          args: [
            "--use-fake-ui-for-media-stream",
            "--use-fake-device-for-media-stream",
            `--use-file-for-fake-audio-capture=${CLIP}`,
          ],
        },
      },
    },
  ],
  webServer: [
    {
      command: `${BIN} --port ${PORT} --console-dir ${DIST}`,
      url: `http://127.0.0.1:${PORT}/console/`,
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command: `${PYTHON} e2e/intent_server.py --port ${INTENT_PORT} --console-dir ${DIST}`,
      url: `http://127.0.0.1:${INTENT_PORT}/console/`,
      reuseExistingServer: false,
      timeout: 30_000,
    },
  ],
});
