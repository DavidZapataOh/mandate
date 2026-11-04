import { expect, test } from "vitest";
import type { Raster } from "../src/shared/raster.ts";
import { hexRgb, keyOut, snapToGrid, WORLD_PALETTE } from "./sprite.ts";

const PALETTE = [hexRgb("000000"), hexRgb("ffffff")] as const;

function raster(w: number, h: number, pixels: number[][]): Raster {
  return { w, h, data: new Uint8ClampedArray(pixels.flat()) };
}

test("keyOut clears pixels within tolerance of the key colour only", () => {
  const r = keyOut(raster(3, 1, [[250, 5, 250, 255], [255, 0, 255, 255], [200, 60, 200, 255]]), hexRgb("ff00ff"), 16);
  expect(Array.from(r.data)).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 200, 60, 200, 255]);
});

test("snapToGrid takes the majority palette colour of each block", () => {
  const src = raster(4, 2, [
    [10, 10, 10, 255], [240, 240, 240, 255], [0, 0, 0, 0], [250, 250, 250, 255],
    [20, 20, 20, 255], [5, 5, 5, 255], [0, 0, 0, 0], [230, 230, 230, 255],
  ]);
  const out = snapToGrid(src, 2, 1, PALETTE);
  expect(Array.from(out.data)).toEqual([0, 0, 0, 255, 255, 255, 255, 255]);
});

test("snapToGrid leaves a block transparent when clear pixels outnumber ink", () => {
  const src = raster(2, 2, [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [255, 255, 255, 255]]);
  expect(Array.from(snapToGrid(src, 1, 1, PALETTE).data)).toEqual([0, 0, 0, 0]);
});

test("snapToGrid output uses only palette colours", () => {
  const src = raster(2, 1, [[60, 120, 90, 255], [250, 240, 230, 255]]);
  const out = snapToGrid(src, 2, 1, WORLD_PALETTE);
  expect(Array.from(out.data)).toEqual([60, 121, 89, 255, 239, 242, 231, 255]);
});
