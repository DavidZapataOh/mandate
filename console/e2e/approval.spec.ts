import { expect, test } from "@playwright/test";
import { agent, pairHolder, startDesk, type Desk } from "./holder";

const MUTED = "rgb(138, 143, 152)";
const VERIFY = "rgb(31, 213, 152)";
const ALERT = "rgb(255, 92, 92)";
const BONE = "rgb(246, 244, 238)";
let desk: Desk;

test.beforeEach(async () => {
  desk = await startDesk(8801);
});

test.afterEach(async ({ browser, page }) => {
  // The holder device polls its desk; close it first so nothing outlives this test's desk.
  for (const context of browser.contexts()) {
    if (context !== page.context()) await context.close();
  }
  await desk.stop();
});

test("the holder approves on their own device and the console follows it to the seal", async ({
  browser,
  page,
}) => {
  const writes: string[] = [];
  page.on("request", (req) => {
    if (req.method() !== "GET") writes.push(new URL(req.url()).pathname);
  });
  await page.goto(`${desk.base}/console/`);
  const approval = page.locator("#approval");
  await expect(approval).toBeHidden();
  const device = await pairHolder(browser, desk);
  expect(agent(desk, "quote", "acme-991", "20000", "USD", "A-991").status).toBe("quoted");
  await expect(approval).toHaveAttribute("data-phase", "waiting");
  await expect(approval.locator(".status")).toHaveCSS("color", MUTED);
  await expect(approval.locator(".amount")).toHaveText("200.00 USD");
  await expect(approval.locator(".payee")).toHaveText("to acme-991");
  const seen = ((await device.locator("#device").textContent()) ?? "").replace("This device ", "");
  expect(seen).toMatch(/^[0-9a-f]{16}$/);
  await expect(approval.locator(".device")).toHaveText("1 holder device paired");
  await device.getByRole("button", { name: "Review" }).click();
  await expect(device.locator("#hash")).toHaveText(/^Consent hash ([0-9a-f]{8} ){7}[0-9a-f]{8}$/);
  const onDevice = ((await device.locator("#hash").textContent()) ?? "").replace("Consent hash ", "");
  await expect(approval.locator(".hash")).toHaveText(onDevice);
  await device.getByRole("button", { name: "Approve" }).click();
  await expect(approval).toHaveAttribute("data-phase", "approved");
  await expect(page.locator("#booth")).toHaveAttribute("data-seal", "wait");
  expect(agent(desk, "confirm", "q:000001").status).toBe("confirmed");
  await expect(approval).toHaveAttribute("data-phase", "paid");
  await expect(approval.locator(".status")).toHaveText("Verified at the gate · paid pay:000001");
  await expect(approval.locator(".status")).toHaveCSS("color", VERIFY);
  // Green belongs to the verdict chip alone; the Paid step stays Bone.
  await expect(approval.locator(".step").last()).toHaveCSS("color", BONE);
  await expect(approval).toHaveAttribute("data-gate", "match");
  await expect(page.locator("#booth")).toHaveAttribute("data-seal", "verify", { timeout: 10_000 });
  expect(writes).toEqual([]);
  await expect(approval.locator("button")).toHaveCount(0);
});

test("an approval signed over altered fields is refused and the console says why", async ({
  browser,
  page,
}) => {
  await page.goto(`${desk.base}/console/`);
  const device = await pairHolder(browser, desk);
  await device.route("**/api/pending", async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as {
      pending: Array<{ consent: { recipient: string } }>;
    };
    for (const quote of body.pending) quote.consent.recipient = "evil-666";
    await route.fulfill({ response, json: body });
  });
  agent(desk, "quote", "acme-991", "20000", "USD", "A-991");
  await device.reload();
  await device.getByRole("button", { name: "Review" }).click();
  await expect(device.locator("#shown")).toContainText("evil-666");
  await device.getByRole("button", { name: "Approve" }).click();
  await expect(device.locator("#status")).toHaveText("approval refused: consent: bad signature");
  const approval = page.locator("#approval");
  await expect(approval).toHaveAttribute("data-phase", "refused");
  await expect(approval.locator(".status")).toHaveText("Approval refused");
  await expect(approval.locator(".status")).toHaveCSS("color", ALERT);
  await expect(approval.locator(".gate .reason")).toHaveText(
    "consent: bad signature. Nothing moved; the quote is still open.",
  );
  await expect(approval.locator(".gate .reason")).toHaveCSS("color", ALERT);
  await expect(approval.locator(".payee")).toHaveText("to acme-991");
  await expect(page.locator("#alert")).toHaveText("denied · consent: bad signature");
  expect(agent(desk, "confirm", "q:000001").status).toBe("quoted");
});

test("the console says when no holder device is paired, then counts it", async ({
  browser,
  page,
}) => {
  await page.goto(`${desk.base}/console/`);
  agent(desk, "quote", "acme-991", "20000", "USD", "A-991");
  const approval = page.locator("#approval");
  await expect(approval.locator(".device")).toHaveText("No holder device paired yet");
  await pairHolder(browser, desk);
  await expect(approval.locator(".device")).toHaveText("1 holder device paired", {
    timeout: 5_000,
  });
});

test("after a paid flow the newest ledger row opens the forensic drawer with a real click", async ({
  browser,
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${desk.base}/console/`);
  const device = await pairHolder(browser, desk);
  agent(desk, "quote", "acme-991", "20000", "USD", "A-991");
  const approval = page.locator("#approval");
  await expect(approval).toHaveAttribute("data-phase", "waiting");
  await device.getByRole("button", { name: "Review" }).click();
  await device.getByRole("button", { name: "Approve" }).click();
  await expect(approval).toHaveAttribute("data-phase", "approved");
  expect(agent(desk, "confirm", "q:000001").status).toBe("confirmed");
  await expect(approval).toHaveAttribute("data-phase", "paid");
  await expect(approval).toBeVisible();
  const newest = page.locator("#ledger button").last();
  await expect(newest).toBeVisible();
  // No force and no scripted click: Playwright fails if another element covers the row.
  await newest.click({ timeout: 5_000 });
  await expect(page.locator("#forensic")).toBeVisible();
});
