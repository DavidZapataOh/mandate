import { expect, type Page, test } from "@playwright/test";

const PAYMENT = process.env.MANDATE_PAYMENT ?? "";

async function verify(page: Page, text: string): Promise<void> {
  await page.locator("#paste").fill(text);
  await page.getByRole("button", { name: "Verify" }).click();
}

test.beforeEach(async ({ page }) => {
  expect(PAYMENT).toMatch(/^pay:[0-9]{6,}$/);
  await page.goto("/console/explorer.html");
  await expect(page.locator("#key-source")).toHaveText("Published by this server");
});

test("a payment made on this desk verifies by its id without its personal fields", async ({ page }) => {
  await verify(page, PAYMENT);
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED, FIELDS WITHHELD");
  await expect(page.locator('#steps li[data-status="pass"]')).toHaveCount(9);
  await page.getByRole("button", { name: "Load the holder copy" }).click();
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED");
  await expect(page.locator('#steps li[data-status="pass"]')).toHaveCount(11);
});

test("its holder copy verifies with the network gone", async ({ page, context, request }) => {
  const receipt = await (await request.get(`/api/receipt/${PAYMENT}?disclose=all`)).text();
  await context.setOffline(true);
  await verify(page, receipt);
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED");
});

test("a copy with a bigger amount fails at the disclosures", async ({ page, request }) => {
  const receipt = await (await request.get(`/api/receipt/${PAYMENT}?disclose=all`)).json();
  const name = (d: string) => JSON.parse(Buffer.from(d, "base64url").toString("utf8"))[1];
  const bigger = Buffer.from(JSON.stringify(["AAAAAAAAAAAAAAAAAAAAAA", "amount_cents", 2000000])).toString("base64url");
  const [token, ...rest] = receipt.sd.split("~");
  receipt.sd = [token, ...rest.slice(0, -1).map((d: string) => (name(d) === "amount_cents" ? bigger : d)), ""].join("~");
  await verify(page, JSON.stringify(receipt));
  await expect(page.locator("#verdict .label")).toHaveText("NOT VERIFIED");
  await expect(page.locator('#steps li[data-status="fail"]')).toHaveAttribute("data-step", "Receipt disclosures");
  await expect(page.locator('#steps li[data-status="pass"]')).toHaveCount(2);
});
