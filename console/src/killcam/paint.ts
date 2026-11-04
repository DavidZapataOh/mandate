import { type SealPose } from "../booth/pose";
import { paintSeal, sealFit } from "../booth/canvas-seal";
import { cueFor } from "../scene/cues";
import { type Atlas, loadAtlas } from "../scene/atlas";
import { blit } from "../scene/render";
import { NATIVE_H, NATIVE_W } from "../scene/stage";
import { createWorld, drawList, pushCue, stepWorld } from "../scene/world";
import type { ConsoleLine } from "../wire/types";

/** Native pixels of the booth with its visitor and floor. */
export const TAPE_CROP = { x: 150, y: 30, w: 150, h: 134 } as const;
/** The booth seal's box, in tape pixels. */
export const TAPE_SEAL = { x: 61, y: 35, w: 22, h: 18 } as const;

let atlas: Promise<Atlas | null> | null = null;
let loaded: Atlas | null = null;
let world: HTMLCanvasElement | null = null;
let seal: HTMLCanvasElement | null = null;
let still: { seq: number; ops: ReturnType<typeof drawList> } | null = null;

/** Paint the booth as it stood when the line arrived, with the seal at a tape pose. */
export function paintBooth(canvas: HTMLCanvasElement, line: ConsoleLine, pose: SealPose): void {
  const ctx = canvas.getContext("2d");
  if (ctx === null) return;
  atlas ??= loadAtlas(import.meta.env.BASE_URL).then(
    (a) => (loaded = a),
    () => null,
  );
  if (still?.seq !== line.seq) {
    // A reduced-motion world puts the line's visitor at the booth in one step.
    const w = createWorld(true);
    pushCue(w, cueFor(line));
    stepWorld(w, 16);
    still = { seq: line.seq, ops: drawList(w) };
  }
  world ??= Object.assign(document.createElement("canvas"), { width: NATIVE_W, height: NATIVE_H });
  seal ??= Object.assign(document.createElement("canvas"), { width: 66, height: 54 });
  const wctx = world.getContext("2d");
  const sctx = seal.getContext("2d");
  if (wctx === null || sctx === null) return;
  ctx.imageSmoothingEnabled = false;
  ctx.fillStyle = "#0B0D10";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  if (loaded !== null) {
    blit(wctx, still.ops, loaded);
    ctx.drawImage(world, TAPE_CROP.x, TAPE_CROP.y, TAPE_CROP.w, TAPE_CROP.h, 0, 0, TAPE_CROP.w, TAPE_CROP.h);
  }
  const [k, dx, dy] = sealFit(66, 54);
  sctx.setTransform(k, 0, 0, k, dx, dy);
  paintSeal(sctx, pose);
  sctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.drawImage(seal, TAPE_SEAL.x, TAPE_SEAL.y, TAPE_SEAL.w, TAPE_SEAL.h);
}
