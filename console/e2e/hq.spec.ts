import { expect, test } from "@playwright/test";
import { attack, deploy, row } from "./attack";

const booth = "#booth";
const stage = "#stage";

test.describe("Nimbus HQ", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/console/");
    await expect(page.locator("#stream-state")).toHaveText("LIVE");
    await expect(page.locator(booth)).toHaveAttribute("data-seal-engine", "rive");
    await expect(page.locator(stage)).toHaveAttribute("data-venue", "bank");
  });

  test("a certified deploy swaps the right world to HQ and verifies at the booth", async ({ page, request }) => {
    const before = Number(await page.locator("#c-verified").textContent());
    const line = JSON.parse(await deploy(request, "release"));
    expect(line.forensic.cert_claims.scope).toBe("nimbus:prod-eu");
    await expect(page.locator(stage)).toHaveAttribute("data-venue", "hq");
    await expect(page.locator("#venue-hq")).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator(booth)).toHaveAttribute("data-seal", "verify", { timeout: 10_000 });
    await expect(page.locator(booth)).toHaveAttribute("data-visitor", "agent");
    const r = row(page, line.seq);
    await expect(r).toHaveAttribute("data-outcome", "pass");
    await expect(r.locator(".origin")).toHaveText("SCENARIO");
    await expect(r.locator(".who")).toHaveText("nimbus scenario");
    await expect(r.locator(".hash")).toHaveText(line.forensic.action_hash.slice(0, 6).toUpperCase());
    await expect(r.locator(".verdict")).toHaveText("VERIFIED");
    await expect(page.locator("#c-verified")).toHaveText(String(before + 1));
  });

  test("a poisoned MCP tool is an intruder thrown out of HQ", async ({ page, request }) => {
    const line = JSON.parse(await deploy(request, "poisoned_tool"));
    await expect(page.locator(stage)).toHaveAttribute("data-venue", "hq");
    await expect(page.locator(booth)).toHaveAttribute("data-visitor", "thief", { timeout: 10_000 });
    await expect(page.locator(booth)).toHaveAttribute("data-seal", "deny");
    await expect(page.locator("#alert")).toHaveText(/^denied · poisoned MCP tool · \d+(µs|\.\dms)$/);
    const r = row(page, line.seq);
    await expect(r).toHaveAttribute("data-outcome", "deny");
    await expect(r.locator("s.hash")).toHaveText(line.forensic.action_hash.slice(0, 6).toUpperCase());
    await expect(r.locator(".text")).toHaveText("Blocked poisoned MCP tool at mcp: denied: tool undeclared");
  });

  test("the venue toggles are disabled while a walker is out and enabled after", async ({ page, request }) => {
    await deploy(request, "poisoned_tool");
    await expect(page.locator(booth)).toHaveAttribute("data-visitor", "thief", { timeout: 10_000 });
    await expect(page.locator("#venue-bank")).toBeDisabled();
    await expect(page.locator("#venue-hq")).toBeDisabled();
    await expect(page.locator("#venue-bank")).toBeEnabled({ timeout: 15_000 });
    await expect(page.locator("#venue-hq")).toBeEnabled();
  });

  test("a stale migration's ghost dies at the booth and opens its record", async ({ page, request }) => {
    const line = JSON.parse(await deploy(request, "stale_migration"));
    await expect(page.locator(booth)).toHaveAttribute("data-visitor", "ghost", { timeout: 10_000 });
    await expect(page.locator(booth)).toHaveAttribute("data-seal", "deny");
    await expect(page.locator("#alert")).toHaveText(/^denied · stale migration · \d+(µs|\.\dms)$/);
    await row(page, line.seq).click();
    await expect(page.locator("#forensic h2")).toHaveText(`Line #${line.seq} · deploy`);
    await expect(page.locator("#forensic")).toContainText("artifact:migration-0017");
  });

  test("a payment line takes the right world back to the bank", async ({ page, request }) => {
    await deploy(request, "release");
    await expect(page.locator(stage)).toHaveAttribute("data-venue", "hq");
    await attack(request, "payee_swap");
    await expect(page.locator(booth)).toHaveAttribute("data-visitor", "forger", { timeout: 15_000 });
    await expect(page.locator(stage)).toHaveAttribute("data-venue", "bank");
    await expect(page.locator("#venue-bank")).toHaveAttribute("aria-pressed", "true");
  });

  test("the presenter opens HQ by hand while the booth is idle", async ({ page }) => {
    await page.locator("#venue-hq").click();
    await expect(page.locator(stage)).toHaveAttribute("data-venue", "hq");
    await expect(page.locator(stage)).toHaveAttribute(
      "aria-label",
      "Nimbus HQ: Meta's agents, the Mandate booth and production",
    );
    await page.locator("#venue-bank").click();
    await expect(page.locator(stage)).toHaveAttribute("data-venue", "bank");
  });
});
