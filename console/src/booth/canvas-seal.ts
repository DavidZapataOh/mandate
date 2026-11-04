import { COLORS } from "virtual:brand";
import type { SealInput } from "../scene/cues";
import type { SealEngine } from "./booth";
import { type SealPose, sealPose } from "./pose";

const TOP = [32, 32, 224, 32, 224, 128, 128, 128, 128, 108, 32, 108] as const;
const BOTTOM = [32, 224, 224, 224, 224, 148, 128, 148, 128, 128, 32, 128] as const;

/** The mark's extent in its 256 grid with the halves fully refused (gap 16) and shaking. */
export const SEAL_BOUNDS = { minX: 16, minY: 16, maxX: 240, maxY: 240 } as const;

/** Scale and offset that fit `SEAL_BOUNDS` centred in a `w`×`h` canvas. */
export function sealFit(w: number, h: number): [k: number, dx: number, dy: number] {
  const { minX, minY, maxX, maxY } = SEAL_BOUNDS;
  const k = Math.min(w / (maxX - minX), h / (maxY - minY));
  return [k, (w - (maxX - minX) * k) / 2 - minX * k, (h - (maxY - minY) * k) / 2 - minY * k];
}

/** Canvas box the whole 256 artboard is drawn into so that `SEAL_BOUNDS` fills the canvas. */
export function sealFrame(w: number, h: number): { minX: number; minY: number; maxX: number; maxY: number } {
  const [k, dx, dy] = sealFit(w, h);
  return { minX: dx, minY: dy, maxX: dx + 256 * k, maxY: dy + 256 * k };
}

function poly(ctx: CanvasRenderingContext2D, pts: readonly number[], dx: number, dy: number): void {
  ctx.beginPath();
  for (let i = 0; i < pts.length; i += 2) {
    const x = (pts[i] ?? 0) + dx;
    const y = (pts[i + 1] ?? 0) + dy;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.closePath();
  ctx.fill();
}

/** Draw one seal pose into a 256 canvas. */
export function paintSeal(ctx: CanvasRenderingContext2D, pose: SealPose): void {
  ctx.clearRect(0, 0, 256, 256);
  ctx.fillStyle = COLORS.ink;
  poly(ctx, TOP, pose.shakeX, -pose.gap);
  poly(ctx, BOTTOM, pose.shakeX, pose.gap);
  if (pose.seam === "none") return;
  ctx.fillStyle = pose.seam === "verify" ? COLORS.verify : COLORS.alert;
  ctx.fillRect(32, 118, 192, 20);
}

/** The seal drawn in canvas, used until the Rive file loads or when it cannot. */
export class CanvasSeal implements SealEngine {
  readonly name = "canvas" as const;
  private input: SealInput = "wait";
  private since: number | null = null;
  private fired = false;

  constructor(
    private readonly ctx: CanvasRenderingContext2D,
    private readonly onState: (s: string) => void,
  ) {}

  fire(input: SealInput): void {
    this.input = input;
    this.fired = true;
    this.since = null;
    this.onState(input);
  }

  draw(now: number): void {
    if (this.since === null) this.since = now;
    paintSeal(this.ctx, sealPose(this.input, this.fired ? now - this.since : 0));
  }
}
