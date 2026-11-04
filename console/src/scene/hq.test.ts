import { expect, test } from "vitest";
import {
  attack,
  bill,
  confirmed,
  gateEvent,
  hook,
  POISONED_SUMMARY,
  refused,
  RELEASE_SUMMARY,
  released,
  STALE_SUMMARY,
} from "./__fixtures__/cases";
import { cueFor, venueOf } from "./cues";
import { createWorld, drawList, pushCue, setVenue, stepWorld, type World } from "./world";

function run(w: World, ms: number): void {
  for (let t = 0; t < ms; t += 16) stepWorld(w, 16);
}

const rightWorld = (w: World) => drawList(w).filter((op) => op.x >= 222 && op.sprite !== "booth").map((op) => op.sprite);

test.each([
  ["desk", "bank", confirmed()],
  ["attack", "bank", attack("mcp_exfil", "mcp")],
  ["bill", "bank", bill(gateEvent("MET", "rule pay-intent satisfied"))],
  ["hook", "hq", hook("MET", "ok")],
  ["deploy", "hq", released()],
] as const)("a %s line plays in the %s world", (_source, venue, line) => {
  expect(venueOf(line)).toBe(venue);
  expect(cueFor(line).venue).toBe(venue);
});

test("the certified release walks from the desks, verifies and is delivered", () => {
  expect(cueFor(released())).toEqual({
    seq: 9, actor: "agent", route: "desk", seal: "verify", outcome: "pass", tag: "nimbus scenario",
    bubble: `${RELEASE_SUMMARY} · released · 18µs`, alert: null, bank: true, venue: "hq",
  });
});

test("the poisoned MCP tool is a thief from the door, denied with the proxy's latency", () => {
  expect(cueFor(refused("poisoned_tool", "mcp", "denied: tool undeclared", { lat_us: 9.0 }))).toEqual({
    seq: 10, actor: "thief", route: "door", seal: "deny", outcome: "deny", tag: "nimbus scenario",
    bubble: POISONED_SUMMARY, alert: "denied · poisoned MCP tool · 9µs", bank: false, venue: "hq",
  });
});

test("the stale migration is the ghost of an old request and dies at the booth", () => {
  const c = cueFor(refused("stale_migration", "gate", "no rule matches"));
  expect([c.actor, c.route, c.seal, c.outcome, c.bubble, c.alert]).toEqual([
    "ghost", "desk", "deny", "deny", STALE_SUMMARY, "denied · stale migration · 18µs",
  ]);
});

test("a refused release dies at the booth and is never delivered", () => {
  const c = cueFor(refused("release", "gate", "stale: token expired"));
  expect([c.actor, c.seal, c.outcome, c.bank, c.bubble]).toEqual(["agent", "deny", "deny", false, `${RELEASE_SUMMARY} · refused`]);
});

test("a deploy step its layer let through is a breach, never a verified seal", () => {
  const c = cueFor(refused("poisoned_tool", "mcp", "ok: declared", { blocked: false }));
  expect([c.outcome, c.seal, c.route, c.alert]).toEqual(["breach", null, "door", "NOT BLOCKED · poisoned MCP tool · ran"]);
});

test("a deploy line swaps the right-hand world to Nimbus HQ when its walker sets out", () => {
  const w = createWorld(false);
  expect(rightWorld(w)).toEqual(["bank", "vault", "clerks"]);
  pushCue(w, cueFor(released()));
  expect(w.venue).toBe("bank");
  stepWorld(w, 16);
  expect([w.venue, w.walker?.cue.seq]).toEqual(["hq", 9]);
  expect(rightWorld(w)).toEqual(["hq", "rack", "ops"]);
});

test("the certified release reaches the prod rack, which lights up", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(released()));
  run(w, 448);
  expect([w.seal, w.visitor]).toEqual(["verify", "agent"]);
  run(w, 832);
  expect(w.envelopeX).toBeNull();
  expect(drawList(w).find((op) => op.sprite === "rack")?.frame).toBe(1);
});

test("a payment line after HQ work takes the right-hand world back to the bank", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(released()));
  pushCue(w, cueFor(attack("payee_swap", "model->gate", { gate: gateEvent("NOT_MET", "recipient differs from intent"), seq: 11 })));
  run(w, 1008);
  expect([w.venue, w.walker?.cue.seq]).toEqual(["hq", 9]);
  run(w, 4000 - 1008);
  expect([w.venue, w.walker?.cue.seq, w.walker?.phase]).toEqual(["bank", 11, "approach"]);
});

test("Muse Code work arriving while a bank walker is out waits its turn, then shows HQ", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(attack("mcp_exfil", "mcp")));
  stepWorld(w, 16);
  pushCue(w, cueFor(hook("NOT_MET", "scope: path escapes worktree")));
  expect([w.venue, w.alert, w.queue.length]).toEqual(["bank", null, 1]);
  run(w, 6000);
  expect([w.venue, w.walker]).toEqual(["hq", null]);
  expect(w.alert).toBe("denied · edit_file · scope: path escapes worktree");
  expect(w.bubbles.map((b) => [b.anchor, b.text])).toEqual([["code", "edit_file src/app.py · denied"]]);
});

test("the presenter can show the other world only while nobody is walking", () => {
  const w = createWorld(false);
  expect(setVenue(w, "hq")).toBe(true);
  expect(rightWorld(w)).toEqual(["hq", "rack", "ops"]);
  pushCue(w, cueFor(confirmed()));
  stepWorld(w, 16);
  expect(w.venue).toBe("bank");
  expect(setVenue(w, "hq")).toBe(false);
  expect(w.venue).toBe("bank");
});

test("allowed Muse Code work that waited out a bank walker only speaks, it never takes the booth", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(attack("mcp_exfil", "mcp")));
  stepWorld(w, 16);
  pushCue(w, cueFor(hook("MET", "rule edit-worktree satisfied")));
  expect(w.queue.length).toBe(1);
  run(w, 6000);
  // The booth keeps the walker's own verdict; the allowed edit never takes it.
  expect([w.venue, w.walker, w.seal, w.visitor]).toEqual(["hq", null, "deny", "thief"]);
  expect(w.bubbles.map((b) => [b.anchor, b.text])).toEqual([["code", "edit_file src/app.py · allowed"]]);
});

const swap = () => attack("payee_swap", "model->gate", { gate: gateEvent("NOT_MET", "recipient differs from intent"), seq: 11 });
const vaultFrameOf = (w: World) => drawList(w).find((op) => op.sprite === "vault" || op.sprite === "rack")?.frame;

function walkersSeen(w: World, ms: number): number[] {
  const seen: number[] = [];
  for (let t = 0; t < ms; t += 16) {
    stepWorld(w, 16);
    const seq = w.walker?.cue.seq;
    if (seq !== undefined && seen[seen.length - 1] !== seq) seen.push(seq);
  }
  return seen;
}

test("allowed chatter never pushes a queued attack out of the queue", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(attack("mcp_exfil", "mcp")));
  stepWorld(w, 16);
  pushCue(w, cueFor(swap()));
  for (let i = 0; i < 10; i++) pushCue(w, cueFor(hook("MET", "ok")));
  expect(walkersSeen(w, 15000)).toContain(11);
});

test("a full queue drops the oldest cue only when every cue carries a verdict", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(attack("mcp_exfil", "mcp")));
  stepWorld(w, 16);
  for (let i = 0; i < 10; i++) pushCue(w, cueFor(attack("payee_swap", "model->gate", { gate: gateEvent("NOT_MET", "x"), seq: 20 + i })));
  expect(w.queue.map((c) => c.seq)).toEqual([22, 23, 24, 25, 26, 27, 28, 29]);
});

test("a blocked bank attack right after a release never shows the bank vault open", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(released()));
  run(w, 1300);
  expect(w.envelopeX).toBeNull();
  expect(vaultFrameOf(w)).toBeGreaterThan(0);
  pushCue(w, cueFor(swap()));
  for (let i = 0; i < 400; i++) {
    stepWorld(w, 16);
    if (w.venue === "bank") expect(vaultFrameOf(w)).toBe(0);
  }
  expect(w.venue).toBe("bank");
});

test("a payment's open vault does not light the prod rack in HQ", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(confirmed()));
  run(w, 1800);
  expect(vaultFrameOf(w)).toBeGreaterThan(0);
  expect(w.venue).toBe("bank");
  expect(setVenue(w, "hq")).toBe(true);
  expect(vaultFrameOf(w)).toBe(0);
  setVenue(w, "bank");
  expect(vaultFrameOf(w)).toBeGreaterThan(0);
});

test("allowed Muse Code work does not switch the world under a held in-place verdict", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(confirmed()));
  run(w, 1800);
  expect(w.walker).toBeNull();
  pushCue(w, cueFor(swap()));
  run(w, 3000);
  stepWorld(w, 16);
  expect(w.walker?.cue.seq).toBe(11);
});

test("verdict-free work of the other venue queues behind a held in-place verdict", () => {
  const w = createWorld(false);
  pushCue(w, { ...cueFor(attack("mcp_exfil", "mcp")), route: "none", seal: "deny" });
  expect(w.t).toBeLessThan(w.holdUntil);
  const venue = w.venue;
  pushCue(w, cueFor(venue === "bank" ? hook("MET", "ok") : confirmed()));
  expect([w.venue, w.queue.length]).toEqual([venue, 1]);
  run(w, 1000);
  expect(w.queue.length).toBe(0);
});

test("allowed Muse Code work queues behind cues that are already waiting", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(attack("mcp_exfil", "mcp")));
  stepWorld(w, 16);
  pushCue(w, cueFor(swap()));
  run(w, 3000);
  pushCue(w, cueFor(hook("MET", "ok")));
  expect(w.queue.length).toBe(2);
});
