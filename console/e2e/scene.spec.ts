import { expect, type Page, test } from "@playwright/test";
import { attack, row } from "./attack";
import { approvedPayment, startConsole } from "./desk";

const booth = "#booth";

test.describe("with the Rive seal", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/console/");
    await expect(page.locator("#stream-state")).toHaveText("LIVE");
    await expect(page.locator(booth)).toHaveAttribute("data-seal-engine", "rive");
  });

  test("a template attack dies at the booth and lands struck in the ledger", async ({ page, request }) => {
    const before = Number(await page.locator("#c-denied").textContent());
    const line = JSON.parse(await attack(request, "mcp_exfil"));
    await expect(page.locator(booth)).toHaveAttribute("data-seal", "deny", { timeout: 10_000 });
    await expect(page.locator(booth)).toHaveAttribute("data-visitor", "thief");
    await expect(page.locator("#alert")).toHaveText("denied · poisoned MCP tool · at the MCP proxy");
    const r = row(page, line.seq);
    await expect(r).toHaveAttribute("data-outcome", "deny");
    await expect(r.locator("s.hash")).toHaveText("------");
    await expect(r.locator(".who")).toHaveText("template attack");
    await expect(r.locator(".verdict")).toHaveText("DENIED");
    await expect(page.locator("#c-denied")).toHaveText(String(before + 1));
  });

  test("a replayed certificate arrives as the ghost and dies at the bank verifier", async ({ page, request }) => {
    const line = JSON.parse(await attack(request, "replay"));
    await expect(page.locator(booth)).toHaveAttribute("data-visitor", "ghost", { timeout: 10_000 });
    await expect(page.locator(booth)).toHaveAttribute("data-seal", "deny");
    await expect(page.locator("#alert")).toHaveText("denied · replayed certificate · at the bank verifier");
    await expect(row(page, line.seq).locator("s.hash")).toHaveText(line.forensic.action_hash.slice(0, 6).toUpperCase());
  });

  test("with reduced motion the verdict lands without the walk, and its bubble opens the drawer", async ({ page, request }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.reload();
    await expect(page.locator(booth)).toHaveAttribute("data-seal-engine", "rive");
    const line = JSON.parse(await attack(request, "scope_escalation"));
    await expect(page.locator(booth)).toHaveAttribute("data-visitor", "brute", { timeout: 1_500 });
    await expect(page.locator(booth)).toHaveAttribute("data-seal", "deny");
    await page.locator(`#overlay button.bubble[data-seq="${line.seq}"]`).click();
    await expect(page.locator("#forensic")).toBeVisible();
    await expect(page.locator("#forensic h2")).toHaveText(`Line #${line.seq} · attack`);
  });

  test("lines already on the server fill the ledger on load without replaying the scene", async ({ page, request }) => {
    const line = JSON.parse(await attack(request, "mcp_exfil"));
    await page.reload();
    await expect(page.locator(booth)).toHaveAttribute("data-seal-engine", "rive");
    await expect(row(page, line.seq)).toHaveAttribute("data-outcome", "deny");
    await page.waitForTimeout(3_000);
    await expect(page.locator(booth)).toHaveAttribute("data-seal", "wait");
    await expect(page.locator(booth)).toHaveAttribute("data-visitor", "");
  });
});

test("without the Rive file the canvas seal still denies", async ({ page, request }) => {
  await page.route("**/rive/seal.riv", (route) => route.abort());
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  await expect(page.locator(booth)).toHaveAttribute("data-seal-engine", "canvas");
  await attack(request, "mcp_exfil");
  await expect(page.locator(booth)).toHaveAttribute("data-seal", "deny", { timeout: 10_000 });
  await expect(page.locator(booth)).toHaveAttribute("data-seal-engine", "canvas");
});

test("a payment verified after a denial never shows the red bar under the green seal", async ({ page }) => {
  const own = await startConsole(8812);
  try {
    await page.goto(`${own.base}/console/`);
    await expect(page.locator(booth)).toHaveAttribute("data-seal-engine", "rive");
    const payment = await approvedPayment(own);
    await attack(page.request, "mcp_exfil", own.base);
    expect(await payment.confirm()).toBe("confirmed");
    await expect(page.locator(booth)).toHaveAttribute("data-seal", "deny", { timeout: 10_000 });
    await expect(page.locator("#alert")).toBeVisible();
    await expect(page.locator(booth)).toHaveAttribute("data-seal", "verify", { timeout: 10_000 });
    await expect(page.locator("#alert")).toBeHidden();
  } finally {
    own.stop();
  }
});

interface BoothFrame {
  visitor: string;
  seal: string;
  alert: boolean;
  bubble: string | null;
}

/** Records the booth on every animation frame, so a test can check what was on screen together. */
async function sampleBooth(page: Page): Promise<() => Promise<BoothFrame[]>> {
  await page.evaluate(() => {
    const frames: BoothFrame[] = [];
    (window as unknown as { __booth: BoothFrame[] }).__booth = frames;
    const tick = (): void => {
      const booth = document.querySelector<HTMLElement>("#booth");
      const alert = document.querySelector<HTMLElement>("#alert");
      const bubble = document.querySelector('#overlay button.bubble[data-anchor="walker"]');
      frames.push({
        visitor: booth?.dataset.visitor ?? "",
        seal: booth?.dataset.seal ?? "",
        alert: alert ? !alert.hidden : false,
        bubble: bubble?.getAttribute("aria-label") ?? null,
      });
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
  return () => page.evaluate(() => (window as unknown as { __booth: BoothFrame[] }).__booth);
}

test("after a template attack the holder-approved payment owns the booth: no red bar under it", async ({ page }) => {
  const own = await startConsole(8813);
  try {
    await page.goto(`${own.base}/console/`);
    await expect(page.locator(booth)).toHaveAttribute("data-seal-engine", "rive");
    const frames = await sampleBooth(page);
    await attack(page.request, "mcp_exfil", own.base);
    const payment = await approvedPayment(own);
    expect(await payment.confirm()).toBe("confirmed");
    await expect(page.locator(booth)).toHaveAttribute("data-seal", "verify", { timeout: 15_000 });
    const seen = await frames();
    expect(seen.some((f) => f.visitor === "thief" && f.seal === "deny" && f.alert)).toBe(true);
    expect(seen.some((f) => f.visitor === "agent" && f.seal === "wait")).toBe(true);
    expect(seen.filter((f) => f.visitor === "agent" && f.alert)).toEqual([]);
    const verified = seen.filter((f) => f.seal === "verify");
    expect(verified.length).toBeGreaterThan(0);
    const paid = /^agent: Pay 42\.00 USD .* · verified/;
    expect(verified.some((f) => paid.test(f.bubble ?? ""))).toBe(true);
    // The bubble expires before the seal reopens; while it shows, it is the payment's.
    expect(verified.filter((f) => f.alert || (f.bubble !== null && !paid.test(f.bubble)))).toEqual([]);
  } finally {
    own.stop();
  }
});

test.describe("on a phone", () => {
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 3 });

  test("the page fits the screen with no sideways scroll and a readable ledger", async ({ page, request }) => {
    await page.goto("/console/");
    await expect(page.locator("#stream-state")).toHaveText("LIVE");
    const line = JSON.parse(await attack(request, "payee_swap"));
    await expect(row(page, line.seq)).toBeVisible();
    const m = await page.evaluate(() => ({
      scroll: document.documentElement.scrollWidth,
      scale: getComputedStyle(document.documentElement).getPropertyValue("--scale").trim(),
      text: Number.parseFloat(getComputedStyle(document.querySelector("#ledger .text") as Element).fontSize),
    }));
    expect(m.scroll).toBeLessThanOrEqual(390);
    expect(m.scale).toBe("2");
    expect(m.text).toBeGreaterThanOrEqual(14);
  });
});
