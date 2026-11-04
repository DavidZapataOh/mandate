import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

const REVIEW = fileURLToPath(new URL("../../.impeccable/review", import.meta.url));
const KINDS = ["payee_swap", "amount_inflate", "replay", "post_cert_mutation", "scope_escalation", "mcp_exfil", "forged_approval"];

test.skip(!process.env["CAPTURE"], "review captures run only with CAPTURE=1");

test.beforeEach(async ({ page, request }) => {
  for (const kind of KINDS) expect((await request.post("/api/attack", { data: { kind } })).ok()).toBe(true);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/console/command.html");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  await expect(page.locator('[data-kind="mcp_exfil"] > *').nth(1)).not.toHaveText("0");
});

test.describe("first viewport at the comp's size", () => {
  // The comp is a 16:9 frame of the 1440-wide layout; render that layout at the comp's own pixel size.
  test.use({ viewport: { width: 1440, height: 810 }, deviceScaleFactor: 2048 / 1440 });

  test("hero", async ({ page }) => {
    await page.screenshot({ path: `${REVIEW}/hero-repro.png` });
  });
});

test("desktop", async ({ page }) => {
  await page.screenshot({ path: `${REVIEW}/desktop.png`, fullPage: true });
});

test("mobile", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: `${REVIEW}/mobile.png`, fullPage: true });
});
