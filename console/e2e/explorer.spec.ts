import { expect, type Page, test } from "@playwright/test";
import { forge, GATE_KEY, RECEIPT, tamper } from "../src/explorer/__fixtures__/receipts";
import OTS from "../src/explorer/__fixtures__/ots.json" with { type: "json" };

async function open(page: Page): Promise<void> {
  await page.goto("/console/explorer.html");
  await expect(page.locator("#key-source")).toHaveText("Published by this server");
}

async function verify(page: Page, text: string): Promise<void> {
  await page.locator("#paste").fill(text);
  await page.getByRole("button", { name: "Verify" }).click();
}

const verdict = (page: Page) => page.locator("#verdict .label");
const failed = (page: Page) => page.locator('#steps li[data-status="fail"]');

test("the explorer starts from the key this server publishes", async ({ page, request }) => {
  const keys = await (await request.get("/api/keys")).json();
  await open(page);
  await expect(page.locator("#gate-key")).toHaveValue(keys.gate_key);
});

test("a receipt this server never signed fails at the gate certificate", async ({ page }) => {
  await open(page);
  await verify(page, RECEIPT);
  await expect(verdict(page)).toHaveText("NOT VERIFIED");
  await expect(failed(page)).toHaveAttribute("data-step", "Gate certificate");
  await expect(page.locator('#steps li[data-status="pass"]')).toHaveCount(1);
});

test("with a pinned key the receipt verifies offline and a forgery fails red", async ({ page, context }) => {
  await open(page);
  await context.setOffline(true);
  await page.locator("#gate-key").fill(GATE_KEY);
  await expect(page.locator("#key-source")).toHaveText("Pinned by you");
  await verify(page, RECEIPT);
  await expect(verdict(page)).toHaveText("VERIFIED");
  await expect(page.locator('#steps li[data-status="pass"]')).toHaveCount(11);
  await verify(page, forge("recipient", "evil-666"));
  await expect(verdict(page)).toHaveText("NOT VERIFIED");
  await expect(failed(page)).toHaveAttribute("data-step", "Receipt disclosures");
  await expect(page.locator('#steps li[data-status="pass"]')).toHaveCount(2);
});

test("a pending public timestamp reads PENDING offline and never as a pass", async ({ page, context }) => {
  await open(page);
  await context.setOffline(true);
  await page.locator("#gate-key").fill(GATE_KEY);
  await verify(page, tamper("public_anchor", { v: 1, ots: OTS.golden.pending, bitcoin: null }));
  await expect(verdict(page)).toHaveText("VERIFIED");
  const step = page.locator('#steps li[data-step="Public anchor"]');
  await expect(step).toHaveAttribute("data-status", "pending");
  await expect(step.locator(".mark")).toHaveText("PENDING");
  await expect(page.locator('#steps li[data-status="pass"]')).toHaveCount(11);
});

test("a payment id needs the server and says so offline", async ({ page, context }) => {
  await open(page);
  await context.setOffline(true);
  await verify(page, "pay:000001");
  await expect(page.locator("#verdict .text")).toHaveText(
    "The server is unreachable; paste the receipt itself to verify offline",
  );
  await expect(page.locator("#steps li")).toHaveCount(0);
});
