import { expect, test } from "vitest";
import { attack, confirmed, desk, hook } from "./__fixtures__/cases";
import { cueFor } from "./cues";
import { ambientFrame, createWorld, drawList, pushCue, setReducedMotion, stepWorld, type World } from "./world";

function run(w: World, ms: number): void {
  for (let t = 0; t < ms; t += 16) stepWorld(w, 16);
}

const THIEF = cueFor(attack("mcp_exfil", "mcp"));

test("a blocked attack walks in from the door and closes the seal on arrival", () => {
  const w = createWorld(false);
  pushCue(w, THIEF);
  run(w, 2352);
  expect([w.seal, w.walker?.phase, w.alert]).toEqual(["wait", "approach", null]);
  run(w, 16);
  expect([w.seal, w.visitor, w.walker?.x, w.walker?.phase]).toEqual(["deny", "thief", 207, "at-booth"]);
  expect(w.alert).toBe("denied · poisoned MCP tool · at the MCP proxy");
});

test("the intruder is thrown back, the seal reopens after 4 s and the alert after 8 s", () => {
  const w = createWorld(false);
  pushCue(w, THIEF);
  run(w, 4752);
  expect(w.walker).toBeNull();
  expect(w.seal).toBe("deny");
  run(w, 6368 - 4752);
  expect([w.seal, w.visitor, w.alert]).toEqual(["wait", null, "denied · poisoned MCP tool · at the MCP proxy"]);
  run(w, 10368 - 6368);
  expect(w.alert).toBeNull();
});

test("a verified payment clears a denial alert still on screen", () => {
  const w = createWorld(false);
  pushCue(w, THIEF);
  pushCue(w, cueFor(confirmed()));
  run(w, 2368);
  expect(w.alert).toBe("denied · poisoned MCP tool · at the MCP proxy");
  let ms = 0;
  while (w.seal !== "verify" && ms < 8000) {
    stepWorld(w, 16);
    ms += 16;
  }
  expect([w.seal, w.alert]).toEqual(["verify", null]);
});

test("a verified payment sends an envelope across that opens the vault", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(confirmed()));
  run(w, 432);
  expect([w.seal, w.envelopeX]).toEqual(["wait", null]);
  run(w, 16);
  expect(w.seal).toBe("verify");
  expect(w.envelopeX).toBeCloseTo(220.536, 3);
  run(w, 832);
  expect(w.envelopeX).toBeNull();
  expect(drawList(w).find((op) => op.sprite === "vault")?.frame).toBe(1);
  run(w, 304);
  expect(drawList(w).find((op) => op.sprite === "vault")?.frame).toBe(3);
});

test("an attack that was not blocked walks through to the bank and never turns the seal green", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(attack("payee_swap", "model->gate", { blocked: false })));
  run(w, 2368);
  expect([w.seal, w.alert]).toEqual(["wait", "NOT BLOCKED · payee swapped · 200.00 moved"]);
  run(w, 800 + 976);
  expect(w.walker).toBeNull();
  expect(w.seal).toBe("wait");
});

test("the booth serves one walker at a time and drops the oldest cue beyond eight", () => {
  const w = createWorld(false);
  for (let seq = 1; seq <= 10; seq++) pushCue(w, { ...THIEF, seq });
  stepWorld(w, 16);
  expect(w.walker?.cue.seq).toBe(3);
  expect(w.queue.map((c) => c.seq)).toEqual([4, 5, 6, 7, 8, 9, 10]);
});

test("in-place cues close the seal at once with a bubble at the Muse Code desks", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(hook("NOT_MET", "scope: path escapes worktree")));
  expect([w.walker, w.seal, w.alert]).toEqual([null, "deny", "denied · edit_file · scope: path escapes worktree"]);
  expect(w.bubbles.map((b) => [b.anchor, b.text])).toEqual([["code", "edit_file src/app.py · denied"]]);
  run(w, 3008);
  expect(w.bubbles).toEqual([]);
});

test("with no events the office keeps typing", () => {
  const w = createWorld(false);
  const frames = [0, 180, 180, 180, 180].map((dt) => {
    stepWorld(w, dt);
    return ambientFrame(w, 180);
  });
  expect(frames).toEqual([0, 1, 2, 3, 0]);
  expect(w.walker).toBeNull();
});

test("reduced motion skips the walk, still denies, and freezes the ambient frames", () => {
  const w = createWorld(true);
  pushCue(w, THIEF);
  stepWorld(w, 16);
  expect([w.seal, w.walker?.x, w.walker?.phase]).toEqual(["deny", 207, "at-booth"]);
  run(w, 10000);
  expect(drawList(w).filter((op) => ["spark", "code-team", "clerks"].includes(op.sprite)).map((op) => op.frame)).toEqual([0, 0, 0]);
});

test("walkers draw over the booth at whole-pixel positions; the replay ghost is translucent", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(attack("replay", "bank")));
  run(w, 1000);
  const ops = drawList(w);
  const booth = ops.findIndex((op) => op.sprite === "booth");
  const ghost = ops.findIndex((op) => op.alpha === 0.5);
  expect(ghost).toBeGreaterThan(booth);
  expect(ops[ghost]?.sprite).toBe("courier");
  expect(ops.every((op) => Number.isInteger(op.x) && Number.isInteger(op.y))).toBe(true);
});

test("the Muse Code courier waits at his post until a desk walk starts", () => {
  const w = createWorld(false);
  expect(drawList(w).filter((op) => op.sprite === "courier")).toEqual([{ sprite: "courier", frame: 0, x: 149, y: 89, alpha: 1 }]);
  pushCue(w, cueFor(desk("quote", "quoted")));
  stepWorld(w, 16);
  expect(drawList(w).filter((op) => op.sprite === "courier").map((op) => [op.x, op.y])).toEqual([[151, 89]]);
});

const walkerOp = (w: World, sprite: string) => drawList(w).find((op) => op.sprite === sprite && op.y !== 89);

test("the visitor clears after a breach like after a denial", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(attack("payee_swap", "model->gate", { blocked: false })));
  run(w, 2368 + 800);
  expect(w.visitor).toBe("forger");
  run(w, 6000);
  expect([w.walker, w.visitor]).toEqual([null, null]);
});

test("walkers face the way they move: flipped while retreating, not while approaching", () => {
  const w = createWorld(false);
  pushCue(w, THIEF);
  run(w, 1000);
  expect(walkerOp(w, "thief")?.flip ?? false).toBe(false);
  run(w, 2368 + 800 + 200 - 1000);
  expect(w.walker?.phase).toBe("retreat");
  expect(walkerOp(w, "thief")?.flip).toBe(true);
});

test("a breach crossing to the bank faces right", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(attack("payee_swap", "model->gate", { blocked: false })));
  run(w, 2368 + 800 + 200);
  expect(w.walker?.phase).toBe("cross");
  expect(walkerOp(w, "forger")?.flip ?? false).toBe(false);
});

test("the thief walk loop uses only the side-on frames 1 to 3", () => {
  const w = createWorld(false);
  pushCue(w, THIEF);
  const seen = new Set<number>();
  for (let i = 0; i < 120; i++) {
    stepWorld(w, 16);
    const op = walkerOp(w, "thief");
    if (op && w.walker?.phase === "approach") seen.add(op.frame);
  }
  expect([...seen].sort()).toEqual([1, 2, 3]);
});

test("reduced motion switched on mid-walk settles the walker and the envelope", () => {
  const w = createWorld(false);
  pushCue(w, THIEF);
  run(w, 1000);
  setReducedMotion(w, true);
  expect([w.seal, w.walker?.x, w.walker?.phase]).toEqual(["deny", 207, "at-booth"]);
  stepWorld(w, 16);
  expect(w.walker).toBeNull();
  const v = createWorld(false);
  pushCue(v, cueFor(confirmed()));
  run(v, 700);
  expect(v.envelopeX).not.toBeNull();
  setReducedMotion(v, true);
  stepWorld(v, 16);
  expect(v.envelopeX).toBeNull();
  expect(drawList(v).find((op) => op.sprite === "vault")?.frame).toBe(3);
});

test("under reduced motion the walker leaves the booth at once", () => {
  const w = createWorld(true);
  pushCue(w, THIEF);
  stepWorld(w, 16);
  expect(w.walker?.phase).toBe("at-booth");
  stepWorld(w, 16);
  expect([w.walker, w.seal]).toEqual([null, "deny"]);
});

/** Steps `ms`, checking at every step that the booth shows only the verdict of the cue at its window. */
function runChecked(w: World, ms: number): void {
  for (let t = 0; t < ms; t += 16) {
    stepWorld(w, 16);
    const walker = w.walker;
    if (walker?.phase !== "at-booth") continue;
    expect([w.visitor, w.seal, w.alert]).toEqual([walker.cue.actor, walker.cue.seal ?? "wait", walker.cue.alert]);
  }
}

test("a quote after a denial never inherits the denial's bar", () => {
  const w = createWorld(false);
  pushCue(w, THIEF);
  pushCue(w, cueFor(desk("quote", "quoted")));
  runChecked(w, 5300);
  expect([w.walker?.cue.actor, w.walker?.phase, w.alert]).toEqual(["agent", "at-booth", null]);
});

test("a breach right after a verified payment never keeps the green seal", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(confirmed()));
  pushCue(w, cueFor(attack("payee_swap", "model->gate", { blocked: false })));
  for (let t = 0; t < 12000; t += 16) {
    stepWorld(w, 16);
    if (w.visitor === "forger") expect(w.seal).not.toBe("verify");
  }
});

test("a breach's bar does not stay under the payment that follows it", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(attack("payee_swap", "model->gate", { blocked: false })));
  pushCue(w, cueFor(desk("quote", "quoted")));
  runChecked(w, 5000);
});

test("a hook denial while a verified payment is at the window waits for the booth to clear", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(confirmed()));
  run(w, 600);
  expect(w.seal).toBe("verify");
  pushCue(w, { ...cueFor(hook("NOT_MET", "scope: target outside delegation")), seq: 9 });
  expect(w.bubbles.map((b) => b.anchor)).toEqual(["walker"]);
  while (w.walker !== null) {
    expect([w.seal, w.alert]).toEqual(["verify", null]);
    stepWorld(w, 16);
  }
  stepWorld(w, 16);
  expect([w.visitor, w.seal, w.alert]).toEqual(["code", "deny", "denied · edit_file · scope: target outside delegation"]);
  expect(w.bubbles.map((b) => b.anchor)).toEqual(["code"]);
});

test("the holder's approval waits until the quoting agent has left the window", () => {
  const w = createWorld(false);
  pushCue(w, cueFor(desk("quote", "quoted")));
  stepWorld(w, 16);
  pushCue(w, { ...cueFor(desk("approve", "approved")), seq: 5 });
  while (w.walker !== null) {
    expect(w.bubbles.some((b) => b.anchor === "booth")).toBe(false);
    stepWorld(w, 16);
  }
  stepWorld(w, 16);
  expect(w.bubbles.find((b) => b.anchor === "booth")?.seq).toBe(5);
});

test("a walker's bubble leaves with it and never rides on the next visitor", () => {
  const w = createWorld(false);
  pushCue(w, THIEF);
  pushCue(w, { ...THIEF, seq: 5 });
  for (let t = 0; t < 7000; t += 16) {
    stepWorld(w, 16);
    if (w.walker?.cue.seq === 5) expect(w.bubbles.filter((b) => b.anchor === "walker" && b.seq !== 5)).toEqual([]);
  }
});
