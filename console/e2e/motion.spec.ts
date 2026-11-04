import { expect, type Page, test } from "@playwright/test";
import { attack, row } from "./attack";
import { ATTACKS } from "./surfaces";

interface Moved {
  readonly target: string;
  readonly property: string;
  readonly duration: number;
  readonly easing: string;
  readonly half: number;
  readonly proof: boolean;
}

/** Record every CSS transition that starts, scrubbed to 60 ms to read its value halfway, and every CSS animation. */
async function watchMotion(page: Page): Promise<() => Promise<Moved[]>> {
  await page.evaluate(() => {
    const w = window as unknown as { moved: Moved[] };
    w.moved = [];
    const proof = (el: Element): boolean => el.closest("#ledger, .counters, #forensic") !== null;
    document.addEventListener("transitionrun", (e) => {
      const el = e.target as HTMLElement;
      for (const a of el.getAnimations()) {
        const t = a.effect?.getTiming();
        if (!(a instanceof CSSTransition) || t === undefined || a.transitionProperty !== e.propertyName) continue;
        a.pause();
        a.currentTime = 60;
        const half = Number(getComputedStyle(el).getPropertyValue(e.propertyName));
        a.play();
        w.moved.push({ target: el.id || el.className, property: e.propertyName, duration: Number(t.duration), easing: t.easing ?? "", half, proof: proof(el) });
      }
    });
    document.addEventListener("animationstart", (e) => {
      const el = e.target as HTMLElement;
      w.moved.push({ target: el.id || el.className, property: `@${e.animationName}`, duration: Number.NaN, easing: "", half: Number.NaN, proof: proof(el) });
    });
  });
  return () => page.evaluate(() => (window as unknown as { moved: Moved[] }).moved);
}

test("the alert bar enters by one opacity fade of 120 ms on the brand ease", async ({ page, request }) => {
  await page.goto("/console/");
  await expect(page.locator("#booth")).toHaveAttribute("data-seal-engine", "rive");
  const moved = await watchMotion(page);
  await attack(request, "mcp_exfil");
  await expect(page.locator("#alert")).toBeVisible({ timeout: 10_000 });
  const alert = (await moved()).filter((m) => m.target === "alert");
  expect(alert.map(({ property, duration, easing }) => ({ property, duration, easing }))).toEqual([
    { property: "opacity", duration: 120, easing: "cubic-bezier(0.16, 1, 0.3, 1)" },
  ]);
  expect(alert[0]!.half).toBeCloseTo(0.9718, 3);
});

test("the seal reports the denial within two frames of the alert bar", async ({ page, request }) => {
  await page.clock.install();
  await page.goto("/console/");
  await expect
    .poll(async () => {
      await page.clock.runFor(50);
      return page.locator("#booth").getAttribute("data-seal-engine");
    })
    .toBe("rive");
  await page.emulateMedia({ reducedMotion: "reduce" });
  await attack(request, "scope_escalation");
  let sealAt = -1;
  let alertAt = -1;
  for (let frame = 0; frame < 300 && (sealAt < 0 || alertAt < 0); frame++) {
    await page.clock.runFor(16);
    if (sealAt < 0 && (await page.locator("#booth").getAttribute("data-seal")) === "deny") sealAt = frame;
    if (alertAt < 0 && (await page.locator("#alert").isVisible())) alertAt = frame;
  }
  expect(sealAt).toBeGreaterThanOrEqual(0);
  expect(Math.abs(sealAt - alertAt)).toBeLessThanOrEqual(2);
});

test("with reduced motion no CSS motion runs and the verdict still lands", async ({ page, request }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/console/");
  await expect(page.locator("#booth")).toHaveAttribute("data-seal-engine", "rive");
  const moved = await watchMotion(page);
  await attack(request, "mcp_exfil");
  await expect(page.locator("#booth")).toHaveAttribute("data-seal", "deny", { timeout: 1_500 });
  await expect(page.locator("#alert")).toBeVisible();
  expect(await moved()).toEqual([]);
});

test("the ledger, the counters and the drawer never move while attacks land", async ({ page, request }) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const moved = await watchMotion(page);
  let last = 0;
  for (const kind of ATTACKS) last = JSON.parse(await attack(request, kind)).seq;
  await row(page, last).click();
  await expect(page.locator("#forensic")).toBeVisible();
  expect((await moved()).filter((m) => m.proof)).toEqual([]);
});

for (const [w, h] of [[1280, 800], [1440, 900], [1600, 1000]] as const) {
  test(`at ${w}x${h} the mismatch shake moves the seal at most 2.5 CSS px`, async ({ page }) => {
    await page.setViewportSize({ width: w, height: h });
    await page.goto("/console/");
    const seal = await page.locator("#seal").boundingBox();
    expect((6 * (seal?.width ?? Number.POSITIVE_INFINITY)) / 256).toBeLessThanOrEqual(2.5);
  });
}
