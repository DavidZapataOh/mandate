import { expect, test } from "@playwright/test";
import { agent, startDesk, type Desk } from "./holder";

let desk: Desk;

test.beforeEach(async () => {
  desk = await startDesk(8803);
});

test.afterEach(async () => {
  await desk.stop();
});

for (const [w, h] of [[1440, 900], [1280, 800], [390, 844]] as const) {
  test(`at ${w}x${h} the panel leaves the booth in view and nothing scrolls sideways`, async ({
    page,
  }) => {
    await page.setViewportSize({ width: w, height: h });
    await page.goto(`${desk.base}/console/`);
    agent(desk, "quote", "acme-991", "20000", "USD", "A-991");
    const approval = page.locator("#approval");
    await expect(approval).toHaveAttribute("data-phase", "waiting");
    const panel = await approval.boundingBox();
    const booth = await page.locator("#booth").boundingBox();
    expect(panel).not.toBeNull();
    expect(booth).not.toBeNull();
    if (panel && booth) {
      const apart =
        panel.x >= booth.x + booth.width ||
        booth.x >= panel.x + panel.width ||
        panel.y >= booth.y + booth.height ||
        booth.y >= panel.y + panel.height;
      expect(apart).toBe(true);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(w);
  });
}

test("below 720px the panel sits right under the stage at full width and never scrolls inside", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${desk.base}/console/`);
  agent(desk, "quote", "acme-991", "20000", "USD", "A-991");
  const approval = page.locator("#approval");
  await expect(approval).toHaveAttribute("data-phase", "waiting");
  const panel = await approval.boundingBox();
  const stage = await page.locator("#stage").boundingBox();
  const strip = await page.locator(".ledger-strip").boundingBox();
  expect(panel).not.toBeNull();
  expect(stage).not.toBeNull();
  expect(strip).not.toBeNull();
  if (panel && stage && strip) {
    expect(panel.y).toBeGreaterThanOrEqual(stage.y + stage.height);
    expect(panel.y + panel.height).toBeLessThanOrEqual(strip.y);
    expect(panel.x).toBeGreaterThanOrEqual(0);
    expect(panel.width).toBeGreaterThanOrEqual(390 - 20);
    expect(panel.x + panel.width).toBeLessThanOrEqual(390);
  }
  expect(await approval.evaluate((el) => el.scrollHeight - el.clientHeight)).toBeLessThanOrEqual(0);
});

test("at 1440x900 the panel ends under its last line, with no trailing empty box", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${desk.base}/console/`);
  agent(desk, "quote", "acme-991", "20000", "USD", "A-991");
  const approval = page.locator("#approval");
  await expect(approval).toHaveAttribute("data-phase", "waiting");
  const gap = await approval.evaluate((el) => {
    const box = el.getBoundingClientRect();
    const last = [...el.children]
      .filter((c) => (c as HTMLElement).offsetParent !== null)
      .map((c) => c.getBoundingClientRect().bottom);
    return box.bottom - Math.max(...last);
  });
  expect(gap).toBeLessThanOrEqual(16);
});

test("phase changes ease in 120 ms and not at all under reduced motion", async ({ page }) => {
  await page.goto(`${desk.base}/console/`);
  agent(desk, "quote", "acme-991", "20000", "USD", "A-991");
  const status = page.locator("#approval .status");
  await expect(status).toHaveText("Waiting for the holder");
  expect(await status.evaluate((el) => getComputedStyle(el).transitionDuration)).toBe("0.12s");
  await page.emulateMedia({ reducedMotion: "reduce" });
  expect(await status.evaluate((el) => getComputedStyle(el).transitionDuration)).toBe("0s");
});
