import { expect, type Page, test } from "@playwright/test";
import { row } from "./attack";

const CASES = [
  ["payee_swap", "Swap the payee", "Killed at Policy rule: recipient differs from intent", 2],
  ["amount_inflate", "Inflate the amount", "Killed at Policy rule: amount differs from intent", 2],
  ["replay", "Replay the certificate", "Killed at Bank verifier: replay: jti consumed", 4],
  ["post_cert_mutation", "Change it after approval", "Killed at Bank verifier: mismatch: action hash differs", 4],
  ["scope_escalation", "Escalate the scope", "Killed at Broker: scope: target outside delegation", 0],
  ["mcp_exfil", "Poison an MCP tool", "Killed at MCP proxy: denied: server undeclared", 0],
  ["forged_approval", "Forge the holder's approval", "Killed at Holder consent: consent: bad signature", 3],
] as const;

interface Line {
  seq: number;
  subject: { attack: string; blocked: boolean; moved_cents: number; origin: string };
  forensic: { action_hash: string } | null;
}

async function press(page: Page, name: string): Promise<Line> {
  const reply = page.waitForResponse((r) => r.url().endsWith("/api/attack") && r.request().method() === "POST");
  await page.getByRole("button", { name: new RegExp(`^${name} TEMPLATE$`) }).click();
  const resp = await reply;
  expect(resp.status()).toBe(200);
  return (await resp.json()) as Line;
}

async function steps(page: Page): Promise<string[]> {
  return page.locator("#killcam ol.steps li").evaluateAll((items) =>
    items.map((li) => `${(li as HTMLElement).dataset.step}:${(li as HTMLElement).dataset.status}`),
  );
}

async function openTape(page: Page, seq: number): Promise<void> {
  await row(page, seq).click();
  await page.locator("#forensic").getByRole("button", { name: "KILL-CAM", exact: true }).click();
  await expect(page.locator("#killcam")).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  await page.getByRole("button", { name: "ATTACK", exact: true }).click();
  await expect(page.locator("#attacks")).toBeVisible();
});

test("each of the seven buttons is denied with zero cents moved and its tape shows the failing layer", async ({ page }) => {
  for (const [kind, name, caption, passed] of CASES) {
    const line = await press(page, name);
    expect(line.subject).toMatchObject({ attack: kind, blocked: true, moved_cents: 0, origin: "template" });
    await expect(page.locator(`#attacks .result[data-kind="${kind}"]`)).toHaveText(new RegExp(`^#${line.seq} denied · `));
    await expect(row(page, line.seq)).toHaveAttribute("data-outcome", "deny");
    await openTape(page, line.seq);
    await expect(page.locator("#killcam .caption")).toHaveText(caption);
    await expect(page.locator('#killcam li[data-status="failed"]')).toHaveCount(1);
    await expect(page.locator('#killcam li[data-status="passed"]')).toHaveCount(passed);
    await expect(page.locator("#killcam .timecode")).toContainText("PLAYBACK");
    await page.locator("#killcam").getByRole("button", { name: "Close" }).click();
    await expect(page.locator("#killcam")).toBeHidden();
  }
});

test("the same press reproduces the same attack and the same tape", async ({ page }) => {
  const first = await press(page, "Replay the certificate");
  await openTape(page, first.seq);
  const before = await steps(page);
  await page.keyboard.press("Escape");
  const second = await press(page, "Replay the certificate");
  await openTape(page, second.seq);
  expect(await steps(page)).toEqual(before);
  expect(second.seq).toBeGreaterThan(first.seq);
  expect(second.forensic!.action_hash).not.toBe(first.forensic!.action_hash);
  expect(second.subject).toEqual(first.subject);
});

test("the tape is driven from the keyboard and lands on the failing step", async ({ page }) => {
  const line = await press(page, "Swap the payee");
  await openTape(page, line.seq);
  await expect(page.locator('#killcam li[aria-current="step"]')).toHaveAttribute("data-step", "policy", { timeout: 5_000 });
  await page.locator("#killcam").getByRole("button", { name: "Previous step" }).press("Enter");
  await expect(page.locator('#killcam li[aria-current="step"]')).toHaveAttribute("data-step", "hash");
  await page.getByRole("slider", { name: "Tape position" }).press("ArrowRight");
  await expect(page.locator('#killcam li[aria-current="step"]')).toHaveAttribute("data-step", "policy");
  await page.keyboard.press("Escape");
  await expect(page.locator("#killcam")).toBeHidden();
  await expect(page.locator("#forensic").getByRole("button", { name: "KILL-CAM", exact: true })).toBeFocused();
});

test("with reduced motion the tape opens paused on the failing step", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  const line = await press(page, "Poison an MCP tool");
  await openTape(page, line.seq);
  await expect(page.locator('#killcam li[aria-current="step"]')).toHaveAttribute("data-step", "mcp");
  await expect(page.locator("#killcam").getByRole("button", { name: "Play" })).toBeVisible();
  await expect(page.locator("#killcam .timecode")).toHaveText("CAM 01 · TELLER · --:--:-- UTC · PLAYBACK · STEP 1/7");
});

test("without --live-attacker the model control is disabled and says why", async ({ page }) => {
  await expect(page.getByRole("button", { name: "Ask the open-weights attacker" })).toBeDisabled();
  await expect(page.locator("#model-status")).toHaveText("Live attacker off: start mandate-console with --live-attacker");
});

test("the Nimbus scenario buttons run the pinned deploy and its two denials get their tapes", async ({ page }) => {
  const run = async (name: string) => {
    const reply = page.waitForResponse((r) => r.url().endsWith("/api/deploy"));
    await page.getByRole("button", { name: `${name} SCENARIO`, exact: true }).click();
    const resp = await reply;
    expect(resp.status()).toBe(200);
    return (await resp.json()) as { seq: number; source: string; subject: { step: string; blocked: boolean } };
  };
  const release = await run("Ship api-v2 to prod-eu");
  expect([release.source, release.subject.blocked]).toEqual(["deploy", false]);
  await expect(row(page, release.seq)).toHaveAttribute("data-outcome", "pass");
  await row(page, release.seq).click();
  await expect(page.locator("#forensic h2")).toHaveText(`Line #${release.seq} · deploy`);
  await expect(page.locator("#forensic").getByRole("button", { name: "KILL-CAM", exact: true })).toHaveCount(0);
  for (const [name, caption] of [
    ["Poison the deploy tool", "Killed at MCP proxy: denied: tool undeclared"],
    ["Re-run migration-0017", "Killed at Policy rule: no rule matches"],
  ] as const) {
    const line = await run(name);
    expect(line.subject.blocked).toBe(true);
    await openTape(page, line.seq);
    await expect(page.locator("#killcam .caption")).toHaveText(caption);
    await expect(page.locator('#killcam li[data-step="target"]')).toHaveAttribute("data-status", "unreached");
    await page.keyboard.press("Escape");
  }
});

test("at 1440x900 the whole panel and the whole tape fit without scrolling", async ({ page }) => {
  const inView = async (locator: ReturnType<Page["locator"]>) => {
    const box = await locator.boundingBox();
    const view = page.viewportSize()!;
    expect(box).not.toBeNull();
    expect(box!.y).toBeGreaterThanOrEqual(0);
    expect(box!.y + box!.height).toBeLessThanOrEqual(view.height);
  };
  await inView(page.getByRole("button", { name: "Re-run migration-0017 SCENARIO", exact: true }));
  await inView(page.getByRole("heading", { name: "Nimbus deploy scenario" }));
  const line = await press(page, "Replay the certificate");
  await openTape(page, line.seq);
  await expect(page.locator('#killcam li[aria-current="step"]')).toHaveAttribute("data-step", "bank", { timeout: 10_000 });
  await inView(page.locator('#killcam li[data-status="failed"]'));
  await inView(page.locator("#killcam ol.steps li").last());
  await inView(page.locator("#killcam .caption"));
});
