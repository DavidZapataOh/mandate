import { MOTION_MS } from "virtual:brand";
import type { SealInput } from "../scene/cues";

export const SNAP_MS = MOTION_MS["seam-snap"];
export const SHAKE_MS = MOTION_MS["mismatch-shake"];
export const OPEN_MS = MOTION_MS["mismatch-open"];

export interface SealPose {
  gap: number;
  shakeX: number;
  seam: "none" | "verify" | "alert";
}

const OPEN = 8;
const REFUSED = 16;
const SHAKE = [-6, 6, -6, 6] as const;

/** Where the seal halves sit at `ms` after the input, in the mark's 256 grid. */
export function sealPose(state: SealInput, ms: number): SealPose {
  if (state === "wait") return { gap: OPEN, shakeX: 0, seam: "none" };
  if (state === "verify") {
    return { gap: Math.max(0, OPEN * (1 - ms / SNAP_MS)), shakeX: 0, seam: "verify" };
  }
  return {
    gap: Math.min(REFUSED, OPEN + (OPEN * ms) / OPEN_MS),
    shakeX: SHAKE[Math.floor(ms / SHAKE_MS)] ?? 0,
    seam: "alert",
  };
}
