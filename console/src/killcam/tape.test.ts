import { expect, test } from "vitest";
import { denial } from "./__fixtures__/denials";
import { killSteps } from "./steps";
import { openTape, pauseTape, playTape, seekTape, stepTape, tapeSeal, tickTape, TAPE_STEP_MS } from "./tape";

const swap = killSteps(denial("payee_swap"))!;
const replay = killSteps(denial("replay"))!;

test("the tape plays one step per beat and stops on the step that killed it", () => {
  let s = openTape(swap, false);
  expect(s).toEqual({ total: 6, end: 3, pos: 1, playing: true, at: 0 });
  s = tickTape(s, TAPE_STEP_MS - 1);
  expect(s.pos).toBe(1);
  s = tickTape(s, 1);
  expect([s.pos, s.playing, s.at]).toEqual([2, true, 0]);
  s = tickTape(s, TAPE_STEP_MS * 5);
  expect([s.pos, s.playing]).toEqual([3, false]);
  expect(tickTape(s, 10_000).pos).toBe(3);
});

test("reduced motion opens paused on the failing step", () => {
  expect(openTape(replay, true)).toEqual({ total: 6, end: 6, pos: 6, playing: false, at: 0 });
});

test("step, seek and pause keep the position inside the played steps", () => {
  const s = openTape(replay, false);
  expect(stepTape(s, -1)).toMatchObject({ pos: 1, playing: false });
  expect(stepTape(stepTape(s, 1), 1)).toMatchObject({ pos: 3, playing: false });
  expect(seekTape(s, 99)).toMatchObject({ pos: 6, playing: false });
  expect(seekTape(s, 0)).toMatchObject({ pos: 1 });
  expect(pauseTape(s)).toMatchObject({ pos: 1, playing: false });
});

test("play at the end rewinds to the first step", () => {
  const done = seekTape(openTape(swap, false), 3);
  expect(playTape(done)).toEqual({ total: 6, end: 3, pos: 1, playing: true, at: 0 });
  expect(playTape(seekTape(done, 2))).toMatchObject({ pos: 2, playing: true });
});

test("the seal waits until the failing step, then refuses to meet", () => {
  const s = openTape(swap, false);
  expect(tapeSeal(s, false)).toEqual({ gap: 8, shakeX: 0, seam: "none" });
  const dead = tickTape(seekTape(s, 3), 50);
  expect(tapeSeal(dead, false)).toEqual({ gap: 12, shakeX: -6, seam: "alert" });
  expect(tapeSeal(dead, true)).toEqual({ gap: 16, shakeX: 0, seam: "alert" });
});
