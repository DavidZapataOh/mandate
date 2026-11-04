import { expect, test, type BrowserContext, type Page } from "@playwright/test";

const SAID = "Pay my Acme Corp bill A-991, 200 USD";

// The desk accepts one paired holder and asks every draft or handoff for that
// device's proof, so the tests share one browser profile, paired once.
let device: BrowserContext;
let page: Page;

test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ browser }, info) => {
  const { baseURL = "", viewport = null } = info.project.use;
  device = await browser.newContext({ baseURL, viewport });
  const pairing = await device.newPage();
  await pairing.goto("/console/holder.html#pair=e2e-pair-token");
  await expect(pairing.locator("#pairing")).toHaveText("Paired with the desk.");
  expect(new URL(pairing.url()).hash).toBe("");
  await pairing.close();
});

test.afterAll(async () => {
  await device.close();
});

test.beforeEach(async () => {
  page = await device.newPage();
});

test.afterEach(async () => {
  await page.close();
});

/** A silent 16 kHz mono WAV one sample longer than ten minutes. */
function tooLong(): Buffer {
  const frames = 600 * 16000 + 1;
  const wav = Buffer.alloc(44 + frames * 2);
  wav.write("RIFF", 0, "ascii");
  wav.writeUInt32LE(36 + frames * 2, 4);
  wav.write("WAVEfmt ", 8, "ascii");
  wav.writeUInt32LE(16, 16);
  wav.writeUInt16LE(1, 20);
  wav.writeUInt16LE(1, 22);
  wav.writeUInt32LE(16000, 24);
  wav.writeUInt32LE(32000, 28);
  wav.writeUInt16LE(2, 32);
  wav.writeUInt16LE(16, 34);
  wav.write("data", 36, "ascii");
  wav.writeUInt32LE(frames * 2, 40);
  return wav;
}

test("the holder signs a typed intent and Muse Spark pays it from the id alone", async ({ request }) => {
  await page.goto("/console/holder.html");
  await page.fill("#intent-text", SAID);
  await page.click("#intent-read");
  await expect(page.locator("#review-recipient")).toHaveText("acme-991");
  await expect(page.locator("#review-amount")).toHaveText("200.00 USD");
  await expect(page.locator("#review-reference")).toHaveText("A-991");
  await page.click("#intent-sign");
  await expect(page.locator("#receipt-id")).toHaveText("i:000001");
  await expect(page.locator("#receipt-funds")).toHaveText(
    "sufficient: desk-signed statement verified on this device.",
  );
  const funds = page.locator("#receipt-funds");
  await expect(funds).toHaveCSS("color", "rgb(31, 213, 152)");
  await funds.evaluate((node) => node.setAttribute("data-verified", "false"));
  await expect(funds).not.toHaveCSS("color", "rgb(31, 213, 152)");
  await funds.evaluate((node) => node.setAttribute("data-verified", "true"));
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  // The full hash stays legible on a phone: at least 10.5px, wrapped inside the stub, never clipped.
  const hash = await page.locator("#receipt-hash").evaluate((node) => ({
    size: parseFloat(getComputedStyle(node).fontSize),
    fits: node.scrollWidth <= node.clientWidth,
    lines: Math.round(node.getBoundingClientRect().height / parseFloat(getComputedStyle(node).lineHeight)),
  }));
  expect(hash.size).toBeGreaterThanOrEqual(10.5);
  expect([hash.fits, hash.lines]).toEqual([true, 2]);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.click("#intent-handoff");
  await expect(page.locator("#agent-state")).toHaveText("Quote q:000001 is waiting for your approval.");
  const approver = await device.newPage();
  await approver.goto("/app/");
  await approver.getByRole("button", { name: "Review" }).click();
  await approver.click("#approve");
  await expect(approver.locator("#shown")).toHaveText("Approved.");
  await expect(page.locator("#agent-state")).toHaveText("Paid: pay:000001.");
  const lines: { subject: { step: string; status: string } }[] = await (await request.get("/api/lines")).json();
  expect(lines.map((l) => [l.subject.step, l.subject.status])).toEqual([
    ["intent", "signed"],
    ["quote", "quoted"],
    ["approve", "approved"],
    ["confirm", "confirmed"],
  ]);
  expect(JSON.stringify(lines)).not.toContain("e2e-pair-token");
});

test("a spoken intent is recorded on the device as the desk's WAV and drafted", async () => {
  await page.goto("/console/holder.html");
  await page.click("#intent-record");
  await expect(page.locator("#intent-status")).toHaveText("Recording. Press Stop when done.");
  await page.waitForTimeout(1500);
  const upload = page.waitForRequest("**/api/intent/voice");
  await page.click("#intent-record");
  const sent = await upload;
  const wav = sent.postDataBuffer() ?? Buffer.alloc(0);
  expect([sent.headers()["content-type"], wav.toString("ascii", 0, 4), wav.readUInt32LE(24)]).toEqual([
    "audio/wav",
    "RIFF",
    16000,
  ]);
  await expect(page.locator("#review-heard")).toHaveText("Pay my Acme Corp bill A-991, 200 USD.");
});

test("a clip over ten minutes never leaves the device", async () => {
  const sent: string[] = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/intent")) sent.push(r.url());
  });
  await page.goto("/console/holder.html");
  await page.setInputFiles("#intent-file", { name: "long.wav", mimeType: "audio/wav", buffer: tooLong() });
  await expect(page.locator("#intent-status")).toHaveText(
    "Clip refused before upload: unsupported wav: longer than 600 s",
  );
  expect(sent).toEqual([]);
});
