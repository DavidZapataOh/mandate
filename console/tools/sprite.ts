import type { Raster } from "../src/shared/raster.ts";

export type Rgb = readonly [number, number, number];

/** Parses a six-digit hex colour (no leading #). */
export function hexRgb(hex: string): Rgb {
  const n = Number.parseInt(hex, 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

export const WORLD_PALETTE: readonly Rgb[] = (
  "070e10 081514 0e1d1b 142d26 062317 1e4b38 2a6c4a 3c7959 55a673 7fd493 cce3c7 eff2e7 62775a 31372f 5f5e2b 989c4e"
).split(" ").map(hexRgb);

/** Clears every pixel within Euclidean RGB distance `tolerance` of `key`. */
export function keyOut(r: Raster, key: Rgb, tolerance: number): Raster {
  const data = new Uint8ClampedArray(r.data);
  for (let i = 0; i < data.length; i += 4) {
    const d = Math.hypot(data[i]! - key[0], data[i + 1]! - key[1], data[i + 2]! - key[2]);
    if (d <= tolerance) data.fill(0, i, i + 4);
  }
  return { w: r.w, h: r.h, data };
}

function nearest(palette: readonly Rgb[], r: number, g: number, b: number): number {
  let best = 0;
  let bestD = Infinity;
  palette.forEach((p, i) => {
    const d = (p[0] - r) ** 2 + (p[1] - g) ** 2 + (p[2] - b) ** 2;
    if (d < bestD) {
      bestD = d;
      best = i;
    }
  });
  return best;
}

/** Reduces `r` to a w by h grid; each cell takes the majority palette colour of its source block. */
export function snapToGrid(r: Raster, w: number, h: number, palette: readonly Rgb[]): Raster {
  const data = new Uint8ClampedArray(w * h * 4);
  const votes = new Array<number>(palette.length);
  for (let gy = 0; gy < h; gy++) {
    const y0 = Math.floor((gy * r.h) / h);
    const y1 = Math.floor(((gy + 1) * r.h) / h);
    for (let gx = 0; gx < w; gx++) {
      const x0 = Math.floor((gx * r.w) / w);
      const x1 = Math.floor(((gx + 1) * r.w) / w);
      votes.fill(0);
      let clear = 0;
      for (let y = y0; y < y1; y++) {
        for (let x = x0; x < x1; x++) {
          const i = (y * r.w + x) * 4;
          if (r.data[i + 3]! < 128) clear++;
          else votes[nearest(palette, r.data[i]!, r.data[i + 1]!, r.data[i + 2]!)]!++;
        }
      }
      let win = 0;
      for (let p = 1; p < palette.length; p++) if (votes[p]! > votes[win]!) win = p;
      if (clear > votes[win]!) continue;
      data.set([...palette[win]!, 255], (gy * w + gx) * 4);
    }
  }
  return { w, h, data };
}
