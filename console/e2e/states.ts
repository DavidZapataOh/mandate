import { expect, type Page } from "@playwright/test";
import { AUDITOR, GATE_KEY, RECEIPT } from "../src/explorer/__fixtures__/receipts";

/** The explorer with the pinned fixture receipt verified: every step shown, the bank transfer and funds proof included. */
export async function verifiedReceipt(page: Page): Promise<void> {
  await page.goto("/console/explorer.html");
  await expect(page.locator("#key-source")).toHaveText("Published by this server");
  await page.locator("#gate-key").fill(GATE_KEY);
  await page.locator("#paste").fill(RECEIPT);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED");
  await expect(page.locator("#steps li")).toHaveCount(11);
  await expect(page.locator('#steps li[data-step="Bank transfer"]')).toBeVisible();
  await expect(page.locator('#steps li[data-step="Funds proof"]')).toBeVisible();
}

/** The explorer with the pinned fixture auditor copy verified: personal fields withheld. */
export async function auditorCopy(page: Page): Promise<void> {
  await page.goto("/console/explorer.html");
  await expect(page.locator("#key-source")).toHaveText("Published by this server");
  await page.locator("#gate-key").fill(GATE_KEY);
  await page.locator("#paste").fill(AUDITOR);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.locator("#verdict")).toHaveAttribute("data-verdict", "withheld");
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED, FIELDS WITHHELD");
}
