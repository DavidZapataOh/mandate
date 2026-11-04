import { expect, test } from "@playwright/test";
import { deploy } from "./attack";

const REVIEW = "../.impeccable/review";

test.skip(!process.env.CAPTURE, "review captures run on demand with CAPTURE=1");

test("hq denial", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.clock.install();
  await page.goto("/console/");
  await expect
    .poll(async () => {
      await page.clock.runFor(50);
      return page.locator("#booth").getAttribute("data-seal-engine");
    })
    .toBe("rive");
  const line = JSON.parse(await deploy(page.request, "poisoned_tool"));
  await expect(page.locator(`#ledger button[data-seq="${line.seq}"]`)).toHaveAttribute("data-outcome", "deny");
  await page.clock.runFor(2800);
  await expect(page.locator("#booth")).toHaveAttribute("data-seal", "deny");
  await expect(page.locator("#stage")).toHaveAttribute("data-venue", "hq");
  await page.screenshot({ path: `${REVIEW}/hq.png`, fullPage: true });
});
