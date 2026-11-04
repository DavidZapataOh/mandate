import { expect, test } from "@playwright/test";
import { attack } from "./attack";
import { auditorCopy, verifiedReceipt } from "./states";
import { CONSOLE_PAGES, GLASSES, SURFACES, textRuns, visit } from "./surfaces";

const LAPTOPS = [[1280, 800], [1440, 900], [1600, 1000]] as const;
const PHONE = [390, 844] as const;

for (const surface of SURFACES) {
  for (const [w, h] of [...LAPTOPS, PHONE, ...(surface === GLASSES ? [[600, 600] as const] : [])]) {
    test(`${surface.name} at ${w}x${h} neither scrolls sideways nor cuts text off`, async ({ page }) => {
      await page.setViewportSize({ width: w, height: h });
      await visit(page, surface);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(w);
      const cut = await page.evaluate(() =>
        [...document.querySelectorAll("body *")]
          .filter((el): el is HTMLElement => el instanceof HTMLElement)
          .filter((el) => {
            const box = el.getBoundingClientRect();
            if (box.width <= 1 || box.height <= 1) return false; // screen-reader-only text is not drawn
            const s = getComputedStyle(el);
            const clips = s.overflowX !== "visible" && s.textOverflow !== "ellipsis";
            const ownText = [...el.childNodes].some((n) => n.nodeType === Node.TEXT_NODE && (n.textContent ?? "").trim() !== "");
            return clips && ownText && el.scrollWidth > el.clientWidth + 1;
          })
          .map((el) => `${el.tagName.toLowerCase()}#${el.id}.${el.className}`),
      );
      expect(cut).toEqual([]);
    });
  }
}

for (const surface of SURFACES) {
  test(`${surface.name} at 1440x900 sets no text under 14 px for the recording`, async ({ page }) => {
    await visit(page, surface);
    const small = (await textRuns(page)).filter((r) => r.size < 14).map((r) => `${r.where} ${r.size}px "${r.text}"`);
    expect(small).toEqual([]);
  });
}

test("the hero signals read at 18 px or more at 1440x900", async ({ page, request }) => {
  await visit(page, CONSOLE_PAGES[0]!);
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  await attack(request, "mcp_exfil");
  await expect(page.locator("#alert")).toBeVisible({ timeout: 10_000 });
  const sizes = await page.evaluate(() =>
    ["#alert", "#ledger .text", ".counters b"].map((sel) => {
      const el = document.querySelector(sel);
      return [sel, el === null ? 0 : Number.parseFloat(getComputedStyle(el).fontSize)] as const;
    }),
  );
  expect(sizes.filter(([, px]) => px < 18)).toEqual([]);
});

test("on the 600x600 glasses display the Approve button is visible without scrolling", async ({ page }) => {
  await page.setViewportSize({ width: 600, height: 600 });
  await visit(page, GLASSES);
  const box = await page.locator("#approve").boundingBox();
  expect((box?.y ?? Number.POSITIVE_INFINITY) + (box?.height ?? 0)).toBeLessThanOrEqual(600);
});

test("the kill-cam tape of a denial sets no text under 14 px at 1440x900", async ({ page, request }) => {
  await visit(page, CONSOLE_PAGES[0]!);
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const line = JSON.parse(await attack(request, "payee_swap"));
  await page.locator(`#ledger button[data-seq="${line.seq}"]`).click();
  await page.locator("#forensic").getByRole("button", { name: "KILL-CAM", exact: true }).click();
  await expect(page.locator("#killcam")).toBeVisible();
  const small = (await textRuns(page)).filter((r) => r.size < 14).map((r) => `${r.where} ${r.size}px "${r.text}"`);
  expect(small).toEqual([]);
});

test("a verified receipt's steps, bank transfer and funds proof included, set no text under 14 px", async ({ page }) => {
  await verifiedReceipt(page);
  const small = (await textRuns(page)).filter((r) => r.size < 14).map((r) => `${r.where} ${r.size}px "${r.text}"`);
  expect(small).toEqual([]);
});

test("the rail label and the holder's funds seam line read at 14 px or more and are never Verify green", async ({ page, request }) => {
  await visit(page, CONSOLE_PAGES[0]!);
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const line = JSON.parse(await attack(request, "replay"));
  const rail = page.locator(`#ledger button[data-seq="${line.seq}"] .rail`);
  await expect(rail).toHaveText("SIMULATED");
  const look = (sel: string) =>
    page.locator(sel).evaluate((el) => [Number.parseFloat(getComputedStyle(el).fontSize) >= 14, getComputedStyle(el).color !== "rgb(31, 213, 152)"]);
  expect(await look(`#ledger button[data-seq="${line.seq}"] .rail`)).toEqual([true, true]);
  await visit(page, CONSOLE_PAGES[3]!);
  expect(await look("#intent-seam")).toEqual([true, true]);
});

test("the holder's receipt stub, its hash, evidence and funds line, and the pairing note read at 14 px or more", async ({ page }) => {
  await visit(page, CONSOLE_PAGES[3]!);
  const sizes = await page.evaluate(() =>
    ["#receipt-hash", "#receipt-evidence", "#intent-receipt .funds", "#pairing"].map((sel) => {
      const el = document.querySelector(sel);
      return [sel, el === null ? 0 : Number.parseFloat(getComputedStyle(el).fontSize)] as const;
    }),
  );
  expect(sizes.filter(([, px]) => px < 14)).toEqual([]);
});

test("withheld fields read as withheld: Muted marks and a Bone label, never Verify green, at 14 px or more", async ({ page }) => {
  await auditorCopy(page);
  const colours = (sel: string) => page.locator(sel).evaluateAll((els) => [...new Set(els.map((el) => getComputedStyle(el).color))]);
  expect(await colours('#steps li[data-status="withheld"] .mark')).toEqual(["rgb(138, 143, 152)"]);
  expect(await colours("#verdict .label")).toEqual(["rgb(246, 244, 238)"]);
  const small = (await textRuns(page)).filter((r) => r.size < 14).map((r) => `${r.where} ${r.size}px "${r.text}"`);
  expect(small).toEqual([]);
});

test("transfers without a certificate turn Alert only when the tile is flagged, and never Verify green", async ({ page }) => {
  await visit(page, CONSOLE_PAGES[2]!);
  const tile = page.locator('[data-metric="unbacked"]');
  const value = tile.locator(".value");
  // The server reconciles the bank rail at start, so the idle value is a calm check with nothing unbacked.
  await expect(value).toHaveText(/^0 of 0 · /);
  const look = () => value.evaluate((el) => [Number.parseFloat(getComputedStyle(el).fontSize) >= 14, getComputedStyle(el).color]);
  const [readable, calm] = await look();
  expect(readable).toBe(true);
  expect(["rgb(31, 213, 152)", "rgb(255, 92, 92)"]).not.toContain(calm);
  await tile.evaluate((el) => el.setAttribute("data-alert", ""));
  expect(await look()).toEqual([true, "rgb(255, 92, 92)"]);
});
