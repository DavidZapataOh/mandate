import { expect, test, type Page, type Route } from "@playwright/test";
import { FIELDS } from "../src/approval/__fixtures__/desk";
import type { ConsentFields } from "../src/approval/consent";
import { CONFIRM, patch } from "../src/wire/__fixtures__/lines";

const REVIEW = "../.impeccable/review/sections";
const BEFORE_EXPIRY = (FIELDS.expires_at - 600) * 1000;
const AFTER_EXPIRY = (FIELDS.expires_at + 1) * 1000;
const PAIRED = { paired: true, fingerprint: "630dcd2966c43366" };
const UNPAIRED = { paired: false, fingerprint: null };
const EVIL: ConsentFields = { ...FIELDS, recipient: "evil-666" };

test.skip(!process.env.CAPTURE, "review captures run on demand with CAPTURE=1");

type Step = "quote" | "approve" | "confirm";

/** One desk line in wire form; only confirm lines carry the gate run. */
function line(
  seq: number,
  step: Step,
  status: string,
  subject: Record<string, unknown> = {},
  top: Record<string, unknown> = {},
): string {
  const gate = step === "confirm" ? {} : { event: null, forensic: null };
  return patch(
    CONFIRM,
    { seq, ...gate, ...top },
    { step, status, quote_id: "q:000001", payment_id: null, reason: null, ...subject },
  );
}

function checked(consent: ConsentFields): Record<string, unknown> {
  return { forensic: { ...JSON.parse(CONFIRM).forensic, consent } };
}

const quoted = (): string => line(1, "quote", "quoted");
const approved = (): string => line(2, "approve", "approved");
const paid = (consent = FIELDS): string =>
  line(3, "confirm", "confirmed", { payment_id: "pay:000001", reason: "ok: executed" }, checked(consent));

interface Desk {
  batches: string[][];
  pending: () => ConsentFields | null | "down";
  device: () => object | "down";
}

function frames(lines: string[], lastSeq: number): string {
  const hello = `event: hello\ndata: ${JSON.stringify({ epoch: "review", last_seq: lastSeq })}\n\n`;
  return `retry: 1000\n${hello}${lines.map((l) => `data: ${l}\n\n`).join("")}`;
}

/** Route the console's desk reads and event stream to pinned fixture lines. */
async function serve(page: Page, desk: Desk): Promise<void> {
  let connection = 0;
  let seq = 0;
  await page.route("**/api/events*", async (route: Route) => {
    const lines = desk.batches[connection] ?? [];
    connection += 1;
    for (const l of lines) seq = Math.max(seq, (JSON.parse(l) as { seq: number }).seq);
    await route.fulfill({ contentType: "text/event-stream", body: frames(lines, seq) });
  });
  await page.route("**/api/pending", async (route: Route) => {
    const fields = desk.pending();
    if (fields === "down") return route.fulfill({ status: 503, body: "" });
    await route.fulfill({
      json: { pending: fields === null ? [] : [{ quote_id: "q:000001", consent: fields }] },
    });
  });
  await page.route("**/api/device", async (route: Route) => {
    const state = desk.device();
    if (state === "down") return route.fulfill({ status: 503, body: "" });
    await route.fulfill({ json: state });
  });
}

async function shoot(
  page: Page,
  name: string,
  desk: Desk,
  phase: string | null,
  options: { time?: number; width?: number; height?: number } = {},
): Promise<void> {
  await page.setViewportSize({ width: options.width ?? 1440, height: options.height ?? 900 });
  await page.clock.install({ time: options.time ?? BEFORE_EXPIRY });
  await serve(page, desk);
  await page.goto("/console/");
  const approval = page.locator("#approval");
  if (phase === null) await expect(approval).toBeHidden();
  else await expect(approval).toHaveAttribute("data-phase", phase);
  await page.clock.runFor(1000);
  await page.screenshot({ path: `${REVIEW}/${name}.png` });
}

const live = (batches: string[][], pending: ConsentFields | null = FIELDS): Desk => ({
  batches,
  pending: () => pending,
  device: () => PAIRED,
});

test("hidden: no quote", async ({ page }) => {
  await shoot(page, "hidden", live([[]], null), null);
});

test("refused: a signature over altered fields", async ({ page }) => {
  const refused = line(2, "approve", "denied", { reason: "consent: bad signature" });
  await shoot(page, "refused", live([[quoted(), refused]]), "refused");
  await expect(page.locator("#approval .status")).toHaveText("Approval refused");
  await expect(page.locator("#approval .gate .reason")).toHaveText(
    "consent: bad signature. Nothing moved; the quote is still open.",
  );
});

test("expired, with no holder device paired", async ({ page }) => {
  const desk: Desk = { ...live([[quoted()]]), device: () => UNPAIRED };
  await shoot(page, "expired-unpaired", desk, "expired", { time: AFTER_EXPIRY });
  await expect(page.locator("#approval .device")).toHaveText("No holder device paired yet");
});

test("approved: waiting for the agent to confirm", async ({ page }) => {
  await shoot(page, "approved", live([[quoted(), approved()]]), "approved");
});

test("approved, fields never seen by this console", async ({ page }) => {
  await shoot(page, "not-seen", live([[quoted(), approved()]], null), "approved");
  await expect(page.locator("#approval .payee")).toHaveText(
    "Consent fields not seen by this console",
  );
});

test("paid: the gate checked the same consent", async ({ page }) => {
  await shoot(page, "paid-match", live([[quoted(), approved(), paid()]]), "paid");
  await expect(page.locator("#approval")).toHaveAttribute("data-gate", "match");
});

test("paid over different consent: mismatch", async ({ page }) => {
  await shoot(page, "paid-mismatch", live([[quoted(), approved(), paid(EVIL)]]), "paid");
  await expect(page.locator("#approval")).toHaveAttribute("data-gate", "mismatch");
  await expect(page.locator("#approval .gate .label")).toHaveCSS("color", "rgb(255, 92, 92)");
  await expect(page.locator("#approval .gate .digest")).toHaveCSS("color", "rgb(255, 92, 92)");
});

test("paid, checked only: this console never saw the quote", async ({ page }) => {
  await shoot(page, "paid-checked", live([[paid()]], null), "paid");
  await expect(page.locator("#approval")).toHaveAttribute("data-gate", "checked");
});

test("denied at the gate", async ({ page }) => {
  const denied = line(3, "confirm", "denied", { reason: "consent: already used" }, checked(FIELDS));
  await shoot(page, "denied", live([[quoted(), approved(), denied]]), "denied");
  // Alert belongs to the refusal reason only; a matching-hash line stays quiet.
  const gate = page.locator("#approval .gate");
  await expect(gate.locator(".reason")).toHaveCSS("color", "rgb(255, 92, 92)");
  await expect(gate.locator(".check")).toHaveText("Gate checked the same consent hash");
  await expect(gate.locator(".check")).toHaveCSS("color", "rgb(246, 244, 238)");
});

test("no WebCrypto: hash unavailable here", async ({ page }) => {
  // An insecure origin (plain http on a LAN address) has no crypto.subtle.
  await page.addInitScript(() => {
    Object.defineProperty(globalThis.crypto, "subtle", { value: undefined });
  });
  await shoot(page, "no-crypto", live([[quoted(), approved(), paid()]]), "paid");
  await expect(page.locator("#approval .gate")).toHaveText(
    "Consent hash unavailable here: needs a secure origin (https or localhost)",
  );
});

test("device state unavailable", async ({ page }) => {
  const desk: Desk = { ...live([[quoted()]]), device: () => "down" };
  await shoot(page, "device-unavailable", desk, "waiting");
  await expect(page.locator("#approval .device")).toHaveText("Holder device state unavailable");
});

test("desk unreachable: last known state kept", async ({ page }) => {
  let down = false;
  const desk: Desk = {
    batches: [[quoted()], [approved()]],
    pending: () => (down ? "down" : FIELDS),
    device: () => PAIRED,
  };
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.clock.install({ time: BEFORE_EXPIRY });
  await serve(page, desk);
  await page.goto("/console/");
  await expect(page.locator("#approval")).toHaveAttribute("data-phase", "waiting");
  down = true;
  await expect(page.locator("#approval .desk-error")).toBeVisible({ timeout: 10_000 });
  await page.screenshot({ path: `${REVIEW}/desk-error.png` });
});

test("replay: the device is not shown", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.clock.install({ time: BEFORE_EXPIRY });
  await page.route("**/replay/review.jsonl", (route) =>
    route.fulfill({ contentType: "application/x-ndjson", body: `${paid()}\n` }),
  );
  await page.goto("/console/?replay=review");
  await page.clock.runFor(3000);
  await expect(page.locator("#approval .device")).toHaveText("Holder device not shown in replay");
  await page.screenshot({ path: `${REVIEW}/replay.png` });
});

test("refused on a phone", async ({ page }) => {
  const refused = line(2, "approve", "denied", { reason: "consent: bad signature" });
  await shoot(page, "refused-mobile", live([[quoted(), refused]]), "refused", {
    width: 390,
    height: 844,
  });
});
