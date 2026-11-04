import { test } from "@playwright/test";
import { GLASSES, visit } from "./surfaces";

const FINISH = "../.impeccable/review/finish";

test.skip(!process.env.CAPTURE, "review captures run on demand with CAPTURE=1");

for (const [file, w, h] of [["glasses-display", 600, 600], ["glasses-mobile", 390, 844]] as const) {
  test(`glasses page ${file}`, async ({ page }) => {
    await page.setViewportSize({ width: w, height: h });
    await visit(page, GLASSES);
    await page.screenshot({ path: `${FINISH}/${file}.png`, fullPage: true });
  });
}
