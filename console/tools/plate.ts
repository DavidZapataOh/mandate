import { PLATE_FACTOR, upscale, type Raster } from "../src/shared/raster.ts";
import { hexRgb, keyOut, snapToGrid, WORLD_PALETTE } from "./sprite.ts";

export interface PlateSpec {
  file: string;
  raw: string;
  crop: readonly [x: number, y: number, w: number, h: number];
  size: readonly [w: number, h: number];
  key: string | null;
}

export const KEY_TOLERANCE = 96;

/** Cuts a sub-rectangle out of `r`. */
export function crop(r: Raster, box: readonly [number, number, number, number]): Raster {
  const [x, y, w, h] = box;
  if (x < 0 || y < 0 || w < 1 || h < 1 || x + w > r.w || y + h > r.h) throw new Error("plate: crop outside the image");
  const data = new Uint8ClampedArray(w * h * 4);
  for (let row = 0; row < h; row++) {
    const s = ((y + row) * r.w + x) * 4;
    data.set(r.data.subarray(s, s + w * 4), row * w * 4);
  }
  return { w, h, data };
}

/** Crop, key the flat ground, snap to the world palette on the native grid, and scale to plate size. */
export function buildPlate(raw: Raster, spec: PlateSpec): Raster {
  const [, , cw, ch] = spec.crop;
  const [w, h] = spec.size;
  const cut = crop(raw, spec.crop);
  if (Math.abs(cw / ch / (w / h) - 1) > 0.02) throw new Error("plate: crop aspect differs from size");
  const keyed = spec.key === null ? cut : keyOut(cut, hexRgb(spec.key), KEY_TOLERANCE);
  return upscale(snapToGrid(keyed, w, h, WORLD_PALETTE), PLATE_FACTOR);
}
