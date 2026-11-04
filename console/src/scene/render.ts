import type { DrawOp } from "../world/sprites";
import type { Atlas } from "./atlas";

export function blit(ctx: CanvasRenderingContext2D, ops: readonly DrawOp[], atlas: Atlas): void {
  ctx.imageSmoothingEnabled = false;
  ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
  for (const op of ops) {
    const frame = atlas.get(op.sprite)?.[op.frame];
    if (!frame) continue;
    ctx.globalAlpha = op.alpha;
    const x = Math.round(op.x);
    const y = Math.round(op.y);
    if (op.flip) {
      ctx.save();
      ctx.translate(x + frame.width, y);
      ctx.scale(-1, 1);
      ctx.drawImage(frame, 0, 0);
      ctx.restore();
    } else {
      ctx.drawImage(frame, x, y);
    }
  }
  ctx.globalAlpha = 1;
}
