import { readFileSync } from "node:fs";
import { expect, type Page, test } from "@playwright/test";

const cell = (page: Page, kind: string, n: number) => page.locator(`[data-kind="${kind}"] > *`).nth(n);

test.beforeEach(async ({ page }) => {
  await page.goto("/console/command.html");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
});

test("a template attack lands in Command blocked, with nothing moved", async ({ page, request }) => {
  const before = Number(await cell(page, "scope_escalation", 1).textContent());
  const res = await request.post("/api/attack", { data: { kind: "scope_escalation" } });
  expect(res.ok()).toBe(true);
  await expect(cell(page, "scope_escalation", 1)).toHaveText(String(before + 1));
  await expect(cell(page, "scope_escalation", 2)).toHaveText(String(before + 1));
  await expect(cell(page, "scope_escalation", 4)).toHaveText("0.00");
  await expect(cell(page, "scope_escalation", 5)).toHaveText("broker");
  await expect(page.locator('[data-metric="moved"] .value')).toHaveText("0.00");
});

test("an attack row drills into its real line and opens the forensic record", async ({ page, request }) => {
  const res = await request.post("/api/attack", { data: { kind: "payee_swap" } });
  const seq = (await res.json()).seq as number;
  await expect(page.locator(`[data-kind="payee_swap"] button.drill`)).not.toHaveText("Show the 0 lines");
  await page.locator(`[data-kind="payee_swap"] button.drill`).click();
  await page.locator(`#drill button[data-seq="${seq}"]`).click();
  await expect(page.locator("#forensic h2")).toHaveText(`Line #${seq} · attack`);
});

test("the JSON export rests on the live registry root and the window it read", async ({ page, request }) => {
  const seq = (await (await request.post("/api/attack", { data: { kind: "mcp_exfil" } })).json()).seq as number;
  await expect(page.locator("#provenance")).toContainText(`to #${seq} (`);
  const served = await (await request.get("/api/provenance")).json();
  const [download] = await Promise.all([page.waitForEvent("download"), page.click("#export-json")]);
  expect(download.suggestedFilename()).toMatch(/^mandate-posture-\d+-\d+\.json$/);
  const report = JSON.parse(readFileSync((await download.path())!, "utf8"));
  expect(report.provenance.registry).toEqual({ root: served.registry.root, leaves: served.registry.leaves, from: "server" });
  expect(report.provenance.policies.map((p: { policy_id: string }) => p.policy_id)).toEqual(["desk", "payments", "nimbus"]);
  expect(report.provenance.window.last).toBeGreaterThanOrEqual(served.window.last_seq);
});

test("the Markdown export opens with the disclaimer", async ({ page }) => {
  const [download] = await Promise.all([page.waitForEvent("download"), page.click("#export-md")]);
  const text = readFileSync((await download.path())!, "utf8");
  expect(text.split("\n").slice(0, 3)).toEqual([
    "# Mandate posture report",
    "",
    "This report maps Mandate controls to framework provisions. It is not a certification, an audit opinion or a statement of compliance.",
  ]);
});

test("a replay plays its recording, never asks the server and says it is a replay", async ({ page, request }) => {
  const recorded: string[] = [];
  for (const kind of ["payee_swap", "mcp_exfil"]) {
    recorded.push(await (await request.post("/api/attack", { data: { kind } })).text());
  }
  const first = JSON.parse(recorded[0]!).seq as number;
  const last = JSON.parse(recorded[1]!).seq as number;
  await page.route("**/console/replay/command.jsonl", (route) =>
    route.fulfill({ status: 200, contentType: "application/x-ndjson", body: recorded.join("\n") }),
  );
  const asked: string[] = [];
  page.on("request", (req) => {
    if (req.url().includes("/api/")) asked.push(req.url());
  });
  await page.goto("/console/command.html?replay=command");
  await expect(page.locator("#stream-state")).toHaveText("REPLAY");
  await expect(page.locator("#provenance")).toHaveText(
    new RegExp(`^Replay command · Lines #${first} to #${last} \\(2 lines\\)( · |$)`),
  );
  await expect(cell(page, "payee_swap", 1)).toHaveText("1");
  await expect(cell(page, "mcp_exfil", 1)).toHaveText("1");
  expect(asked).toEqual([]);
});

test("an unsafe replay name stops the page at REPLAY ERROR", async ({ page }) => {
  await page.goto("/console/command.html?replay=..%2Fsecret");
  await expect(page.locator("#stream-state")).toHaveText("REPLAY ERROR");
  await expect(page.locator("#tiles article")).toHaveCount(0);
});

test("the page runs under the console CSP without a violation", async ({ page }) => {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(err.message));
  await page.reload();
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  await expect(page.locator("#provenance")).toContainText("(server)");
  await page.locator('[data-metric="decided"] button.drill').click();
  await expect(page.locator("#drill")).toBeVisible();
  const [download] = await Promise.all([page.waitForEvent("download"), page.click("#export-md")]);
  expect(download.suggestedFilename()).toMatch(/^mandate-posture-(\d+-\d+|empty)\.md$/);
  expect(errors).toEqual([]);
});

test("on a phone the register stacks each provision: GOVERN 1.4 shows its evidence and gap, with no nested scroll", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const row = page.locator('#controls tr[data-control="NIST AI RMF 1.0 GOVERN 1.4"]');
  await row.scrollIntoViewIfNeeded();
  await expect(page.locator("#controls thead")).toBeHidden();
  for (const cell of [row.locator(".evidence"), row.locator("td").nth(4)]) {
    await cell.scrollIntoViewIfNeeded();
    await expect(cell).toBeInViewport({ ratio: 1 });
  }
  const register = page.locator("#controls .register");
  const box = await register.evaluate((el) => [el.scrollHeight, el.clientHeight, el.scrollWidth, el.clientWidth]);
  expect([box[0], box[2]]).toEqual([box[1], box[3]]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
});

test("the register fades at its foot until it is scrolled to its end", async ({ page }) => {
  const register = page.locator("#controls .register");
  await expect(register).toHaveAttribute("data-at-end", "false");
  await register.evaluate((el) => el.scrollTo({ top: el.scrollHeight }));
  await expect(register).toHaveAttribute("data-at-end", "true");
});
