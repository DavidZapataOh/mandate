import { expect, type Page, test } from "@playwright/test";
import { AUDITOR, forge, GATE_KEY, RECEIPT, regate } from "../src/explorer/__fixtures__/receipts";

const REVIEW = "../.impeccable/review";

test.skip(!process.env.CAPTURE, "review captures run on demand with CAPTURE=1");

async function forged(page: Page, width: number, height: number): Promise<void> {
  await page.setViewportSize({ width, height });
  // Captures show settled states: no colour transition caught halfway.
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/console/explorer.html");
  await expect(page.locator("#key-source")).toHaveText("Published by this server");
  await page.locator("#gate-key").fill(GATE_KEY);
  await page.locator("#paste").fill(forge("amount_cents", 2000000));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.locator("#verdict .label")).toHaveText("NOT VERIFIED");
  await page.evaluate(() => document.fonts.ready);
  // A reader checks a paste from its first line: show the receipt from the top, as pasted.
  await page.locator("#paste").evaluate((el) => {
    el.scrollTop = 0;
  });
}

// The approved comp is this page at 1440x900 drawn at 4/3: the hero gate reads the same pixels.
test.describe(() => {
  test.use({ deviceScaleFactor: 4 / 3 });

  test("explorer hero", async ({ page }) => {
    await forged(page, 1440, 900);
    await page.screenshot({ path: `${REVIEW}/hero-repro.png` });
  });
});

test("explorer desktop", async ({ page }) => {
  await forged(page, 1440, 900);
  await page.screenshot({ path: `${REVIEW}/desktop.png`, fullPage: true });
});

test("explorer mobile", async ({ page }) => {
  await forged(page, 390, 844);
  await page.screenshot({ path: `${REVIEW}/mobile.png`, fullPage: true });
});

// Every other state the page can be in, for the sections review.
const STATES: Record<string, () => Promise<string> | string> = {
  verified: () => RECEIPT,
  withheld: () => AUDITOR,
  certificate: () => (JSON.parse(RECEIPT) as { certificate: string }).certificate,
  refused: () => "not a receipt",
  "late-failure": () => regate("amount_cents", 2000000),
};

for (const [name, text] of Object.entries(STATES)) {
  test(`explorer section ${name}`, async ({ page }) => {
    await forged(page, 1440, 900);
    await page.locator("#paste").fill(await text());
    await page.getByRole("button", { name: "Verify" }).click();
    await expect(page.locator("#verdict")).not.toHaveAttribute("data-verdict", name === "late-failure" ? "verified" : "failed");
    await page.screenshot({ path: `${REVIEW}/sections/${name}.png`, fullPage: true });
  });
}

test("explorer section auditor copy", async ({ page }) => {
  await forged(page, 1440, 900);
  await page.locator("#paste").fill(RECEIPT);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED");
  await page.getByLabel("Amount").check();
  await page.getByRole("button", { name: "Make the auditor copy" }).click();
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED, FIELDS WITHHELD");
  await page.screenshot({ path: `${REVIEW}/sections/auditor-copy.png`, fullPage: true });
});

test("explorer section mobile verified", async ({ page }) => {
  await forged(page, 390, 844);
  await page.locator("#paste").fill(RECEIPT);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED");
  await page.screenshot({ path: `${REVIEW}/sections/mobile-verified.png`, fullPage: true });
});

for (const width of [1280, 1600]) {
  test(`explorer section desktop ${width}`, async ({ page }) => {
    await forged(page, width, 900);
    await page.screenshot({ path: `${REVIEW}/sections/desktop-${width}.png`, fullPage: true });
  });
}
