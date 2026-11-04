import { expect, test } from "@playwright/test";
import { attack, row } from "./attack";

const SWAP = "Blocked payee swap at model->gate: recipient differs from intent";

test("a template attack lands in the ledger and opens its forensic detail", async ({
  page,
  request,
}) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const line = JSON.parse(await attack(request, "payee_swap"));
  await expect(row(page, line.seq).locator(".origin")).toHaveText("TEMPLATE");
  await expect(row(page, line.seq).locator(".text")).toHaveText(SWAP);
  expect(line.forensic.action_hash).toMatch(/^[0-9a-f]{64}$/);
  const time = await row(page, line.seq).locator(".t").textContent();
  await expect(
    page.getByRole("button", {
      name: `TEMPLATE · ${time} · template attack · ${SWAP} · (hash) ${line.forensic.action_hash.slice(0, 6).toUpperCase()} (struck) · DENIED`,
      exact: true,
    }),
  ).toHaveAttribute("data-seq", String(line.seq));
  await row(page, line.seq).click();
  const drawer = page.locator("#forensic");
  await expect(drawer).toBeVisible();
  await expect(drawer.locator("section", { hasText: "Action hash" }).locator("pre")).toHaveText(
    line.forensic.action_hash,
  );
  await expect(
    drawer.locator("section", { hasText: "Certificate claims" }).locator("pre"),
  ).toHaveText("No certificate issued");
});

test("forensic mode shows the hash prefix of every row", async ({ page, request }) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const line = JSON.parse(await attack(request, "payee_swap"));
  await page.getByRole("button", { name: "FORENSIC" }).click();
  await expect(row(page, line.seq).locator(".text")).toHaveText(
    `#${line.seq} attack NOT_MET ${line.forensic.action_hash.slice(0, 12)} recipient differs from intent`,
  );
  await expect(page.getByRole("button", { name: "FORENSIC" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
});

test("a dropped stream resumes after the last event id", async ({ page, request }) => {
  const before = JSON.parse(await attack(request, "replay"));
  const first = await attack(request, "payee_swap");
  const after = JSON.parse(await attack(request, "mcp_exfil"));
  const seq = JSON.parse(first).seq;
  let dropped = false;
  await page.route("**/api/events*", async (route) => {
    if (dropped) return route.continue();
    dropped = true;
    // One frame, then the response ends: the browser reconnects with Last-Event-ID.
    return route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      body: `retry: 200\nid: ${seq}\ndata: ${first}\n\n`,
    });
  });
  await page.goto("/console/");
  await expect(row(page, after.seq)).toHaveCount(1);
  await expect(row(page, seq)).toHaveCount(1);
  await expect(row(page, before.seq)).toHaveCount(0);
});

test("a restarted server closes the drawer of the old run", async ({ page, request }) => {
  const text = await attack(request, "payee_swap");
  const seq = JSON.parse(text).seq;
  let release = (): void => {};
  const restarted = new Promise<void>((resolve) => {
    release = resolve;
  });
  let opened = 0;
  await page.route("**/api/events*", async (route) => {
    opened += 1;
    if (opened > 1) {
      await restarted;
      return route.continue();
    }
    // A stream from another process: its epoch differs from the real server's.
    return route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      body: `retry: 200\nevent: hello\ndata: {"epoch": "0000000000000000", "last_seq": ${seq}}\n\nid: ${seq}\ndata: ${text}\n\n`,
    });
  });
  await page.goto("/console/");
  await row(page, seq).click();
  const drawer = page.locator("#forensic");
  await expect(drawer).toBeVisible();
  release();
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  await expect(drawer).toBeHidden();
  await expect(drawer.locator("*")).toHaveCount(0);
});

test("replay plays a recorded stream as live showed it, labeled REPLAY", async ({
  page,
  request,
}) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const recorded = [await attack(request, "amount_inflate"), await attack(request, "scope_escalation")];
  const seqs = recorded.map((text) => JSON.parse(text).seq as number);
  for (const seq of seqs) await expect(row(page, seq)).toHaveCount(1);
  const live = await Promise.all(seqs.map((seq) => row(page, seq).textContent()));
  await page.route("**/console/replay/e2e.jsonl", (route) =>
    route.fulfill({ status: 200, contentType: "application/x-ndjson", body: recorded.join("\n") }),
  );
  await page.goto("/console/?replay=e2e");
  await expect(page.locator("#stream-state")).toHaveText("REPLAY");
  // Replay is paced by the scene: the second line lands once the first visitor has left.
  await expect(page.locator("#ledger button")).toHaveCount(2, { timeout: 15_000 });
  const replayed = await page.locator("#ledger button").allTextContents();
  expect(replayed).toEqual([...live].reverse());
  await expect(page.locator("#stream-state")).toHaveText("REPLAY");
});

test("replay keeps the ledger in step with the scene: never more than one row ahead of the booth", async ({ page, request }) => {
  await page.goto("/console/");
  await expect(page.locator("#stream-state")).toHaveText("LIVE");
  const recorded: string[] = [];
  for (const kind of ["mcp_exfil", "payee_swap", "scope_escalation", "replay"]) recorded.push(await attack(request, kind));
  await page.route("**/console/replay/paced.jsonl", (route) =>
    route.fulfill({ status: 200, contentType: "application/x-ndjson", body: recorded.join("\n") }),
  );
  await page.addInitScript(() => {
    const out = { ahead: 0, animated: [] as string[] };
    (window as unknown as { __paced: typeof out }).__paced = out;
    const tick = (): void => {
      for (const b of document.querySelectorAll<HTMLElement>("#overlay button.bubble")) {
        const seq = b.dataset.seq ?? "";
        if (!out.animated.includes(seq)) out.animated.push(seq);
      }
      const rows = document.querySelectorAll("#ledger button").length;
      out.ahead = Math.max(out.ahead, rows - out.animated.length);
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
  await page.goto("/console/?replay=paced");
  await expect(page.locator("#stream-state")).toHaveText("REPLAY");
  await expect(page.locator("#ledger button")).toHaveCount(4, { timeout: 30_000 });
  const paced = () => page.evaluate(() => (window as unknown as { __paced: { ahead: number; animated: string[] } }).__paced);
  expect((await paced()).ahead).toBeLessThanOrEqual(1);
  await expect.poll(async () => (await paced()).animated.length, { timeout: 10_000 }).toBe(4);
  expect((await paced()).ahead).toBeLessThanOrEqual(1);
  expect([...(await paced()).animated].sort()).toEqual(recorded.map((t) => String(JSON.parse(t).seq)).sort());
});
