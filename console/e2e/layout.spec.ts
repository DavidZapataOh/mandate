import { expect, type Page, test } from "@playwright/test";
import { attack, row } from "./attack";
import { approvedPayment, startConsole } from "./desk";

interface Overlap {
  /** How far a walker bubble's bottom reaches below the visible alert's top (CSS px). */
  alert: number[];
  /** Area any bubble covers of the TELLER sign, and which anchors were seen. */
  sign: number[];
  /** Clearance (CSS px) between a booth bubble's bottom and the sign's top, where they share columns. */
  clear: number[];
  anchors: string[];
}

/** Measures, on every frame, how bubbles sit against the alert bar and the booth sign. */
async function sampleOverlap(page: Page): Promise<() => Promise<Overlap>> {
  await page.evaluate(() => {
    const out: Overlap = { alert: [], sign: [], clear: [], anchors: [] };
    (window as unknown as { __overlap: Overlap }).__overlap = out;
    const tick = (): void => {
      const alert = document.querySelector<HTMLElement>("#alert");
      const sign = (document.querySelector(".sign") as Element).getBoundingClientRect();
      for (const b of document.querySelectorAll<HTMLElement>("#overlay button.bubble")) {
        const r = b.getBoundingClientRect();
        const anchor = b.dataset.anchor ?? "";
        if (!out.anchors.includes(anchor)) out.anchors.push(anchor);
        if (anchor === "walker" && alert && !alert.hidden) out.alert.push(r.bottom - alert.getBoundingClientRect().top);
        const dx = Math.min(r.right, sign.right) - Math.max(r.left, sign.left);
        const dy = Math.min(r.bottom, sign.bottom) - Math.max(r.top, sign.top);
        out.sign.push(dx > 0 && dy > 0 ? dx * dy : 0);
        if (anchor === "booth" && dx > 0) out.clear.push(sign.top - r.bottom);
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
  return () => page.evaluate(() => (window as unknown as { __overlap: Overlap }).__overlap);
}

test.describe("stage geometry", () => {
  for (const [w, h, cssW, cssH] of [[1440, 900, 1332, 492], [1280, 800, 1332, 492], [1600, 1000, 1776, 656], [390, 844, 888, 328]] as const) {
    test(`at ${w}x${h} the world is drawn at an integer scale with no smoothing`, async ({ page }) => {
      await page.setViewportSize({ width: w, height: h });
      await page.goto("/console/");
      const world = page.locator("#world");
      await expect(world).toHaveAttribute("width", "444");
      await expect(world).toHaveAttribute("height", "164");
      const box = await world.boundingBox();
      expect([box?.width, box?.height]).toEqual([cssW, cssH]);
      expect(await world.evaluate((el) => getComputedStyle(el).imageRendering)).toBe("pixelated");
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(w);
      const booth = await page.locator("#booth").boundingBox();
      expect(Math.abs((booth?.x ?? 0) + (booth?.width ?? 0) / 2 - w / 2)).toBeLessThanOrEqual(2);
    });
  }
});

test("only the verdict moment moves: the alert and bubbles fade in fast, the ledger and counters never animate", async ({ page, request }) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const line = JSON.parse(await attack(request, "mcp_exfil"));
  await expect(row(page, line.seq)).toBeVisible();
  await expect(page.locator("#alert")).toBeVisible();
  await expect(page.locator("#overlay .bubble").first()).toBeVisible();
  const motion = await page.evaluate(() => {
    const css = (sel: string) => {
      const s = getComputedStyle(document.querySelector(sel) as Element);
      return [s.animationName, s.transitionProperty, s.transitionDuration, s.transitionTimingFunction].join(" | ");
    };
    return { alert: css("#alert"), bubble: css("#overlay .bubble"), row: css("#ledger button"), counter: css("#c-denied") };
  });
  expect(motion).toEqual({
    alert: "none | opacity | 0.12s | cubic-bezier(0.16, 1, 0.3, 1)",
    bubble: "none | opacity | 0.12s | cubic-bezier(0.16, 1, 0.3, 1)",
    row: "none | all | 0s | ease",
    counter: "none | all | 0s | ease",
  });
});

test("below 720px the counters wrap under the wordmark, rows drop to 16px and the booth sign stays legible", async ({ page, request }) => {
  await page.setViewportSize({ width: 700, height: 900 });
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const line = JSON.parse(await attack(request, "payee_swap"));
  await expect(row(page, line.seq)).toBeVisible();
  const mark = await page.locator(".wordmark").boundingBox();
  const counters = await page.locator(".counters").boundingBox();
  expect(counters?.y ?? 0).toBeGreaterThanOrEqual((mark?.y ?? 0) + (mark?.height ?? 0));
  const sizes = await row(page, line.seq).evaluate((el) =>
    [".t", ".hash", ".text"].map((sel) => {
      const cell = el.querySelector(sel) as HTMLElement;
      const s = getComputedStyle(cell);
      return [sel, s.fontSize, s.textOverflow, cell.getBoundingClientRect().width > 0];
    }),
  );
  expect(sizes).toEqual([
    [".t", "16px", "clip", true],
    [".hash", "16px", "clip", true],
    [".text", "16px", "ellipsis", true],
  ]);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => row(page, line.seq).locator(".who").evaluate((el) => el.scrollWidth <= el.clientWidth && el.clientWidth > 0)).toBe(true);
  expect(await row(page, line.seq).locator(".hash").evaluate((el) => getComputedStyle(el, "::before").content)).toBe("none");
  await expect.poll(() => page.locator(".sign").evaluate((el) => Number.parseFloat(getComputedStyle(el).fontSize))).toBeGreaterThanOrEqual(14);
});

test("at 1280x700 (scale 2) the alert stays at 14px or more and the attack's bubble ends above it", async ({ page, request }) => {
  await page.setViewportSize({ width: 1280, height: 700 });
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  expect(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--scale").trim())).toBe("2");
  const overlap = await sampleOverlap(page);
  await attack(request, "post_cert_mutation");
  await expect(page.locator("#alert")).toBeVisible({ timeout: 10_000 });
  expect(await page.locator("#alert").evaluate((el) => Number.parseFloat(getComputedStyle(el).fontSize))).toBeGreaterThanOrEqual(14);
  const box = await page.locator("#alert").boundingBox();
  expect(box?.height ?? 0).toBeGreaterThanOrEqual(20);
  await page.waitForTimeout(1_000);
  const seen = await overlap();
  expect(seen.alert.length).toBeGreaterThan(0);
  expect(Math.max(...seen.alert)).toBeLessThanOrEqual(0);
});

for (const [w, h, port] of [[1440, 900, 8815], [1600, 1000, 8814]] as const) {
  test(`at ${w}x${h} the Muse Spark tag sits whole inside the stage and no bubble covers the TELLER sign`, async ({ page }) => {
    const own = await startConsole(port);
    try {
      await page.setViewportSize({ width: w, height: h });
      await page.goto(`${own.base}/console/`);
      await expect(page.locator("#stream-state")).toHaveText("LIVE");
      await expect
        .poll(async () => {
          const stage = await page.locator("#stage").boundingBox();
          const tag = await page.locator('#overlay > .tag[data-anchor="spark"]').boundingBox();
          if (!stage || !tag) return false;
          return tag.x >= stage.x && tag.x + tag.width <= stage.x + stage.width && tag.y >= stage.y;
        })
        .toBe(true);
      const bar = await page.locator(".bar").boundingBox();
      expect(bar?.x ?? 0).toBeGreaterThanOrEqual(12);
      const overlap = await sampleOverlap(page);
      const payment = await approvedPayment(own);
      expect(await payment.confirm()).toBe("confirmed");
      await expect(page.locator("#booth")).toHaveAttribute("data-seal", "verify", { timeout: 15_000 });
      const seen = await overlap();
      expect(seen.anchors).toContain("booth");
      expect(Math.max(0, ...seen.sign)).toBe(0);
      // The bubble keeps the overlay's 4px gap above the sign, never resting on its glyphs.
      expect(Math.min(...seen.clear)).toBeGreaterThanOrEqual(4);
    } finally {
      own.stop();
    }
  });
}
