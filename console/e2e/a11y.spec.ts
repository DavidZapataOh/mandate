import AxeBuilder from "@axe-core/playwright";
import { expect, type Locator, type Page, test } from "@playwright/test";
import { attack, row } from "./attack";
import { auditorCopy, verifiedReceipt } from "./states";
import { GLASSES, SURFACES, visit } from "./surfaces";

const WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

/** axe violations of serious or critical impact, one line per rule with its targets. */
async function blocking(page: Page): Promise<string[]> {
  const result = await new AxeBuilder({ page }).withTags(WCAG).analyze();
  return result.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

/** Press Tab until target holds focus; fails after limit presses. */
async function tabTo(page: Page, target: Locator, limit = 80): Promise<void> {
  for (let i = 0; i < limit; i++) {
    if (await target.evaluate((el) => el === document.activeElement)) return;
    await page.keyboard.press("Tab");
  }
  throw new Error(`Tab never reached ${target}`);
}

for (const surface of SURFACES) {
  test(`${surface.name} has no serious or critical axe violation`, async ({ page }) => {
    await visit(page, surface);
    expect(await blocking(page)).toEqual([]);
  });

  test(`${surface.name}: Tab reaches every visible control and each shows the Bone ring`, async ({ page }) => {
    await visit(page, surface);
    const total = await page.evaluate(() => {
      const controls = [
        ...document.querySelectorAll<HTMLElement>(
          "a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), summary, [tabindex]:not([tabindex='-1'])",
        ),
      ].filter((el) => el.getClientRects().length > 0 && getComputedStyle(el).visibility === "visible");
      controls.forEach((el, i) => {
        el.dataset.tabProbe = String(i);
      });
      return controls.length;
    });
    const reached = new Set<string>();
    const rings = new Set<string>();
    for (let i = 0; i <= total; i++) {
      await page.keyboard.press("Tab");
      const at = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        if (el === null || el.dataset.tabProbe === undefined) return null;
        const s = getComputedStyle(el);
        return { probe: el.dataset.tabProbe, ring: `${s.outlineStyle} ${s.outlineWidth} ${s.outlineColor}` };
      });
      if (at !== null) {
        reached.add(at.probe);
        rings.add(at.ring);
      }
    }
    expect(reached.size).toBe(total);
    expect([...rings]).toEqual(total === 0 ? [] : [surface === GLASSES ? "solid 4px rgb(246, 244, 238)" : "solid 2px rgb(246, 244, 238)"]);
  });
}

test("the forensic view of a denial, drawer open, has no serious or critical axe violation", async ({ page, request }) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const line = JSON.parse(await attack(request, "payee_swap"));
  await page.locator("#mode-forensic").click();
  await row(page, line.seq).click();
  await expect(page.locator("#forensic")).toBeVisible();
  expect(await blocking(page)).toEqual([]);
});

test("the keyboard opens a ledger row's forensic record and Escape returns to the row", async ({ page, request }) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const line = JSON.parse(await attack(request, "mcp_exfil"));
  const target = row(page, line.seq);
  await tabTo(page, target);
  await page.keyboard.press("Enter");
  await expect(page.locator("#forensic")).toBeVisible();
  await expect(page.locator("#forensic h2")).toBeFocused();
  await attack(request, "payee_swap");
  await page.keyboard.press("Escape");
  await expect(page.locator("#forensic")).toBeHidden();
  await expect(target).toBeFocused();
});

test("the open attack panel has no serious or critical axe violation", async ({ page }) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  await page.getByRole("button", { name: "ATTACK", exact: true }).click();
  await expect(page.locator("#attacks")).toBeVisible();
  expect(await blocking(page)).toEqual([]);
});

test("the kill-cam tape of a denial has no serious or critical axe violation", async ({ page, request }) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const line = JSON.parse(await attack(request, "payee_swap"));
  await row(page, line.seq).click();
  await page.locator("#forensic").getByRole("button", { name: "KILL-CAM", exact: true }).click();
  await expect(page.locator("#killcam")).toBeVisible();
  expect(await blocking(page)).toEqual([]);
});

test("a ledger row with its rail label has no serious or critical axe violation", async ({ page, request }) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const line = JSON.parse(await attack(request, "replay"));
  await expect(row(page, line.seq).locator(".rail")).toHaveText("SIMULATED");
  expect(await blocking(page)).toEqual([]);
});

test("a verified receipt with its bank transfer and funds proof steps has no serious or critical axe violation", async ({ page }) => {
  await verifiedReceipt(page);
  expect(await blocking(page)).toEqual([]);
});

test("the auditor copy with its withheld fields has no serious or critical axe violation", async ({ page }) => {
  await auditorCopy(page);
  expect(await blocking(page)).toEqual([]);
});

test("the keyboard ticks a field and makes an auditor copy that withholds the rest", async ({ page }) => {
  await verifiedReceipt(page);
  const amount = page.locator('input[name="reveal"][value="amount"]');
  await tabTo(page, amount);
  await page.keyboard.press("Space");
  await expect(amount).toBeChecked();
  await tabTo(page, page.locator("#present"));
  await page.keyboard.press("Enter");
  await expect(page.locator("#presentation")).not.toHaveValue("");
  await expect(page.locator("#verdict .label")).toHaveText("VERIFIED, FIELDS WITHHELD");
});
