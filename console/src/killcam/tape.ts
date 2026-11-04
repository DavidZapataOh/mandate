import type { SealPose } from "../booth/pose";
import { sealPose } from "../booth/pose";
import type { KillStep } from "./steps";

export const TAPE_STEP_MS = 900;
const SETTLED_MS = 320;

export interface TapeState {
  readonly total: number;
  readonly end: number;
  readonly pos: number;
  readonly playing: boolean;
  readonly at: number;
}

/** A tape on its first step, or paused on the failing step under reduced motion. */
export function openTape(steps: readonly KillStep[], reducedMotion: boolean): TapeState {
  const failed = steps.findIndex((s) => s.status === "failed");
  const end = (failed === -1 ? steps.length - 1 : failed) + 1;
  return reducedMotion
    ? { total: steps.length, end, pos: end, playing: false, at: 0 }
    : { total: steps.length, end, pos: 1, playing: true, at: 0 };
}

/** Advance the clock; a playing tape moves one step per beat and stops on the failing step. */
export function tickTape(s: TapeState, dtMs: number): TapeState {
  let { pos, playing, at } = s;
  at += dtMs;
  while (playing && at >= TAPE_STEP_MS) {
    at -= TAPE_STEP_MS;
    pos += 1;
    if (pos >= s.end) {
      pos = s.end;
      playing = false;
    }
  }
  return { ...s, pos, playing, at };
}

/** Play, from the first step when the tape is at its end. */
export function playTape(s: TapeState): TapeState {
  return s.pos >= s.end ? { ...s, pos: 1, playing: true, at: 0 } : { ...s, playing: true };
}

export function pauseTape(s: TapeState): TapeState {
  return { ...s, playing: false };
}

/** Jump to a step (clamped to the played steps) and pause. */
export function seekTape(s: TapeState, pos: number): TapeState {
  return { ...s, pos: Math.min(s.end, Math.max(1, Math.round(pos))), playing: false, at: 0 };
}

export function stepTape(s: TapeState, delta: 1 | -1): TapeState {
  return seekTape(s, s.pos + delta);
}

/** The seal waits until the failing step, then refuses to meet. */
export function tapeSeal(s: TapeState, reducedMotion: boolean): SealPose {
  if (s.pos < s.end) return sealPose("wait", 0);
  return sealPose("deny", reducedMotion ? SETTLED_MS : s.at);
}
