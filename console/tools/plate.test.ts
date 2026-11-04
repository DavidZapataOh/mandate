import { expect, test } from "vitest";
import type { Raster } from "../src/shared/raster.ts";
import { buildPlate } from "./plate.ts";

const M = [255, 0, 255, 255];
const W = [255, 255, 255, 255];

function grid(rows: number[][][]): Raster {
  return { w: rows[0]!.length, h: rows.length, data: new Uint8ClampedArray(rows.flat(2)) };
}

const RAW = grid([
  [M, M, M, M],
  [M, W, W, M],
  [M, W, W, M],
  [M, M, M, M],
]);

test("buildPlate snaps the crop to the world palette at six times native size", () => {
  const plate = buildPlate(RAW, { file: "x.png", raw: "x.webp", crop: [1, 1, 2, 2], size: [1, 1], key: null });
  expect([plate.w, plate.h]).toEqual([6, 6]);
  expect(new Set(Array.from(plate.data).join(",").match(/\d+,\d+,\d+,\d+/g))).toEqual(new Set(["239,242,231,255"]));
});

test("buildPlate turns the magenta ground into transparent pixels", () => {
  const plate = buildPlate(RAW, { file: "x.png", raw: "x.webp", crop: [0, 0, 4, 4], size: [2, 2], key: "ff00ff" });
  expect(Array.from(plate.data).every((v) => v === 0)).toBe(true);
});

test("buildPlate refuses a crop outside the generated image", () => {
  expect(() => buildPlate(RAW, { file: "x.png", raw: "x.webp", crop: [2, 2, 4, 4], size: [1, 1], key: null })).toThrow(
    "plate: crop outside the image",
  );
});

test("buildPlate refuses a crop that would squash the sprite", () => {
  expect(() => buildPlate(RAW, { file: "x.png", raw: "x.webp", crop: [0, 0, 4, 2], size: [1, 1], key: null })).toThrow(
    "plate: crop aspect differs from size",
  );
});
