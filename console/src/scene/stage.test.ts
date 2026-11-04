import { expect, test } from "vitest";
import { fitStage } from "./stage";

test.each([
  [1376, 768, { scale: 3, width: 1332, height: 492, cropX: 0 }],
  [1440, 900, { scale: 3, width: 1332, height: 492, cropX: 0 }],
  [1280, 800, { scale: 3, width: 1280, height: 492, cropX: 26 }],
  [1600, 1000, { scale: 4, width: 1600, height: 656, cropX: 88 }],
  [1920, 1080, { scale: 4, width: 1776, height: 656, cropX: 0 }],
  [390, 844, { scale: 2, width: 390, height: 328, cropX: 249 }],
])("fitStage(%i, %i) keeps an integer scale centred on the booth", (w, h, want) => {
  expect(fitStage(w, h)).toEqual(want);
});
