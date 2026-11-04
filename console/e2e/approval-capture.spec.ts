import { expect, test, type Browser, type Page } from "@playwright/test";
import { agent, pairHolder, startDesk, type Desk } from "./holder";

const REVIEW = "../.impeccable/review";

test.skip(!process.env.CAPTURE, "review captures run on demand with CAPTURE=1");

let desk: Desk;

test.beforeEach(async () => {
  desk = await startDesk(8802);
});

test.afterEach(async ({ browser, page }) => {
  // The holder device polls its desk; close it first so nothing outlives this test's desk.
  for (const context of browser.contexts()) {
    if (context !== page.context()) await context.close();
  }
  await desk.stop();
});

async function pending(page: Page, browser: Browser, w: number, h: number): Promise<void> {
  await page.setViewportSize({ width: w, height: h });
  await page.clock.install();
  await page.goto(`${desk.base}/console/`);
  await pairHolder(browser, desk);
  agent(desk, "quote", "acme-991", "20000", "USD", "A-991");
  await expect(page.locator("#approval")).toHaveAttribute("data-phase", "waiting");
  await page.clock.runFor(2800);
}

// The approved comp is this console at 1440x900 drawn at 4/3: capture the same pixels.
test.describe(() => {
  test.use({ deviceScaleFactor: 4 / 3 });

  test("approval hero plates only", async ({ browser, page }) => {
    await pending(page, browser, 1440, 900);
    // The console CSP refuses inline style tags; CSSOM writes are allowed.
    await page.evaluate(() => {
      for (const el of document.querySelectorAll<HTMLElement>(
        "header, #overlay, #alert, #ledger, #approval",
      )) {
        el.style.visibility = "hidden";
      }
    });
    await page.screenshot({ path: `${REVIEW}/hero-plates.png` });
  });

  test("approval hero", async ({ browser, page }) => {
    await pending(page, browser, 1440, 900);
    await page.screenshot({ path: `${REVIEW}/hero-repro.png` });
  });
});

test("approval desktop", async ({ browser, page }) => {
  await pending(page, browser, 1440, 900);
  await page.screenshot({ path: `${REVIEW}/desktop.png`, fullPage: true });
});

test("approval mobile", async ({ browser, page }) => {
  await pending(page, browser, 390, 844);
  await page.screenshot({ path: `${REVIEW}/mobile.png`, fullPage: true });
});
