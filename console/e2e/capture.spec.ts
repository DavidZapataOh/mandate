import { expect, type Page, test } from "@playwright/test";
import { attack } from "./attack";

const REVIEW = "../.impeccable/review";

test.skip(!process.env.CAPTURE, "review captures run on demand with CAPTURE=1");

async function denial(page: Page, w: number, h: number): Promise<void> {
  await page.setViewportSize({ width: w, height: h });
  // Real lines already on the server fill the ledger below the hero denial, as in the comp.
  for (const kind of ["payee_swap", "replay", "scope_escalation", "amount_inflate", "post_cert_mutation"]) {
    await attack(page.request, kind);
  }
  await page.clock.install();
  await page.goto("/console/");
  await expect
    .poll(async () => {
      await page.clock.runFor(50);
      return page.locator("#booth").getAttribute("data-seal-engine");
    })
    .toBe("rive");
  const line = JSON.parse(await attack(page.request, "mcp_exfil"));
  await expect(page.locator(`#ledger button[data-seq="${line.seq}"]`)).toHaveAttribute("data-outcome", "deny");
  await page.clock.runFor(2800);
  await expect(page.locator("#booth")).toHaveAttribute("data-seal", "deny");
}

test("hero plates only", async ({ page }) => {
  await denial(page, 1376, 768);
  // The console CSP refuses inline style tags; CSSOM writes are allowed.
  await page.evaluate(() => {
    for (const el of document.querySelectorAll<HTMLElement>("header, #overlay, #alert, #ledger")) {
      el.style.visibility = "hidden";
    }
  });
  await page.screenshot({ path: `${REVIEW}/hero-plates.png` });
});

test("hero", async ({ page }) => {
  await denial(page, 1376, 768);
  await page.screenshot({ path: `${REVIEW}/hero-repro.png` });
});

test("desktop", async ({ page }) => {
  await denial(page, 1440, 900);
  await page.screenshot({ path: `${REVIEW}/desktop.png`, fullPage: true });
});

test("mobile", async ({ page }) => {
  await denial(page, 390, 844);
  await page.screenshot({ path: `${REVIEW}/mobile.png`, fullPage: true });
});
