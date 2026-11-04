import { expect, test } from "@playwright/test";
import { attack } from "./attack";
import { ATTACKS, CONSOLE_PAGES, SURFACES, visit } from "./surfaces";

interface Vitals {
  readonly fcp: number;
  readonly lcp: number;
  readonly cls: number;
}

for (const surface of SURFACES) {
  test(`${surface.name} paints first within 1 s, largest within 2 s, and shifts under 0.05`, async ({ page }) => {
    await visit(page, surface);
    await page.waitForTimeout(1_000);
    const vitals = await page.evaluate(
      () =>
        new Promise<Vitals>((done) => {
          const fcp = performance.getEntriesByName("first-contentful-paint")[0]?.startTime ?? Number.POSITIVE_INFINITY;
          let cls = 0;
          for (const e of performance.getEntriesByType("layout-shift") as unknown as { value: number; hadRecentInput: boolean }[]) {
            if (!e.hadRecentInput) cls += e.value;
          }
          new PerformanceObserver((list) => {
            done({ fcp, lcp: list.getEntries().at(-1)?.startTime ?? Number.POSITIVE_INFINITY, cls });
          }).observe({ type: "largest-contentful-paint", buffered: true });
        }),
    );
    expect(vitals.fcp).toBeLessThanOrEqual(1_000);
    expect(vitals.lcp).toBeLessThanOrEqual(2_000);
    expect(vitals.cls).toBeLessThanOrEqual(0.05);
  });
}

for (const surface of SURFACES.filter((s) => s.name !== "console")) {
  test(`${surface.name} never fetches the seal runtime`, async ({ page }) => {
    const fetched: string[] = [];
    page.on("request", (r) => fetched.push(new URL(r.url()).pathname));
    await visit(page, surface);
    await page.waitForTimeout(1_000);
    expect(fetched.filter((p) => /rive|\.wasm$/.test(p))).toEqual([]);
  });
}

test("ten attacks in one burst keep frames under 20 ms at p95 and no frame blocks over 100 ms", async ({ page, request }) => {
  await visit(page, CONSOLE_PAGES[0]!);
  await expect(page.locator("#booth")).toHaveAttribute("data-seal-engine", "rive");
  const before = await page.locator("#ledger button").count();
  await page.evaluate(() => {
    const w = window as unknown as { deltas: number[]; longest: number; sampling: boolean };
    w.deltas = [];
    w.longest = 0;
    w.sampling = true;
    new PerformanceObserver((list) => {
      for (const e of list.getEntries()) w.longest = Math.max(w.longest, e.duration);
    }).observe({ type: "long-animation-frame" });
    let last = performance.now();
    const tick = (now: number): void => {
      w.deltas.push(now - last);
      last = now;
      if (w.sampling) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
  await Promise.all(Array.from({ length: 10 }, (_, i) => attack(request, ATTACKS[i % ATTACKS.length]!)));
  await expect(page.locator("#ledger button")).toHaveCount(Math.min(before + 10, 200));
  await page.waitForTimeout(3_000);
  const { deltas, longest } = await page.evaluate(() => {
    const w = window as unknown as { deltas: number[]; longest: number; sampling: boolean };
    w.sampling = false;
    return { deltas: w.deltas.slice(1), longest: w.longest };
  });
  const sorted = [...deltas].sort((a, b) => a - b);
  expect(sorted.length).toBeGreaterThan(150);
  expect(sorted[Math.floor(sorted.length * 0.95)]!).toBeLessThanOrEqual(20);
  expect(longest).toBeLessThanOrEqual(100);
});
