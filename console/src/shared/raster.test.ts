import { expect, test } from "vitest";
import { decimate, upscale, type Raster } from "./raster";

const RED = [255, 0, 0, 255];
const BLUE = [0, 0, 255, 255];
const pair: Raster = { w: 2, h: 1, data: new Uint8ClampedArray([...RED, ...BLUE]) };

function px(r: Raster, x: number, y: number): number[] {
  const i = (y * r.w + x) * 4;
  return Array.from(r.data.subarray(i, i + 4));
}

test("upscale repeats each pixel as a k by k block", () => {
  const big = upscale(pair, 3);
  expect([big.w, big.h]).toEqual([6, 3]);
  expect(px(big, 2, 2)).toEqual(RED);
  expect(px(big, 3, 0)).toEqual(BLUE);
});

test("decimate recovers the native pixels of an upscaled plate", () => {
  const back = decimate(upscale(pair, 6), 6);
  expect([back.w, back.h]).toEqual([2, 1]);
  expect(Array.from(back.data)).toEqual([...RED, ...BLUE]);
});

test("decimate refuses a plate whose blocks are not uniform", () => {
  const big = upscale(pair, 6);
  big.data.set(BLUE, (1 * 12 + 4) * 4);
  expect(() => decimate(big, 6)).toThrow("raster: not a x6 pixel grid");
});

test("decimate refuses dimensions that are not a multiple of k", () => {
  expect(() => decimate({ w: 7, h: 6, data: new Uint8ClampedArray(7 * 6 * 4) }, 6)).toThrow(
    "raster: not a x6 pixel grid",
  );
});
