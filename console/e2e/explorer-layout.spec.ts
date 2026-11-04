import { expect, type Page, test } from "@playwright/test";
import { AUDITOR, forge, GATE_KEY, RECEIPT, tamper } from "../src/explorer/__fixtures__/receipts";
import OTS from "../src/explorer/__fixtures__/ots.json" with { type: "json" };

async function forged(page: Page): Promise<void> {
  await page.goto("/console/explorer.html");
  await expect(page.locator("#key-source")).toHaveText("Published by this server");
  await page.locator("#gate-key").fill(GATE_KEY);
  await page.locator("#paste").fill(forge("amount_cents", 2000000));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.locator("#verdict .label")).toHaveText("NOT VERIFIED");
}

const color = (page: Page, selector: string) =>
  page.locator(selector).first().evaluate((el) => getComputedStyle(el).color);
const fill = (page: Page, selector: string) =>
  page.locator(selector).first().evaluate((el) => getComputedStyle(el).backgroundColor);
const INK = "rgb(11, 13, 16)";

for (const width of [1280, 1440, 1600, 390]) {
  test(`the verdict and the failing step sit in the first viewport at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    await forged(page);
    const height = page.viewportSize()!.height;
    const shown = width === 390 ? ["#verdict"] : ["#verdict", '#steps li[data-status="fail"]'];
    for (const selector of shown) {
      const box = await page.locator(selector).boundingBox();
      expect(box && box.y + box.height).toBeLessThanOrEqual(height);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);
  });
}

for (const width of [1280, 1600]) {
  test(`a pending public anchor sets its detail under the row, as a withheld step does, at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await forged(page);
    await page.locator("#paste").fill(tamper("public_anchor", { v: 1, ots: OTS.golden.pending, bitcoin: null }));
    await page.getByRole("button", { name: "Verify" }).click();
    const step = page.locator('#steps li[data-step="Public anchor"]');
    await expect(step).toHaveAttribute("data-status", "pending");
    const [mark, name, detail] = await Promise.all(
      [step.locator(".mark"), step.locator("h3"), step.locator("p")].map((l) => l.boundingBox()),
    );
    expect(detail!.y).toBeGreaterThanOrEqual(mark!.y + mark!.height - 1);
    expect(detail!.x).toBeLessThanOrEqual(name!.x + 1);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);
  });
}

test("green belongs to passed steps and red to the failed one only", async ({ page }) => {
  await forged(page);
  expect(await fill(page, '#steps li[data-status="pass"] .mark')).toBe("rgb(31, 213, 152)");
  expect(await fill(page, '#steps li[data-status="fail"] .mark')).toBe("rgb(255, 92, 92)");
  expect(await fill(page, '#steps li[data-status="unchecked"] .mark')).toBe("rgb(138, 143, 152)");
  for (const status of ["pass", "fail", "unchecked"]) {
    expect(await color(page, `#steps li[data-status="${status}"] .mark`)).toBe(INK);
  }
  expect(await color(page, "#verdict .label")).toBe("rgb(255, 92, 92)");
  await page.locator("#paste").fill(RECEIPT);
  await page.getByRole("button", { name: "Verify" }).click();
  expect(await color(page, "#verdict .label")).toBe("rgb(31, 213, 152)");
});

test("a verdict with withheld fields is never green", async ({ page }) => {
  await forged(page);
  await page.locator("#paste").fill(AUDITOR);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED, FIELDS WITHHELD");
  expect(await color(page, "#verdict .label")).toBe("rgb(246, 244, 238)");
  expect(await fill(page, '#steps li[data-status="withheld"] .mark')).toBe(INK);
  expect(await color(page, '#steps li[data-status="withheld"] .mark')).toBe("rgb(138, 143, 152)");
});

test("hashes and keys are set in JetBrains Mono, prose in Inter", async ({ page }) => {
  await forged(page);
  // Reveals are drawn only for a receipt whose disclosures verify: read them from the holder copy.
  await page.locator("#paste").fill(RECEIPT);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED");
  const family = (selector: string) =>
    page.locator(selector).first().evaluate((el) => getComputedStyle(el).fontFamily);
  expect(await family("#gate-key")).toMatch(/^"?JetBrains Mono/);
  expect(await family("#reveals dd")).toMatch(/^"?JetBrains Mono/);
  expect(await family("#steps li p")).toMatch(/^"?Inter/);
});
