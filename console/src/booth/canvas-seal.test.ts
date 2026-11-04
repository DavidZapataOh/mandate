import { expect, test } from "vitest";
import { SEAL_BOUNDS, sealFit, sealFrame } from "./canvas-seal";
import { sealPose } from "./pose";

test("the seal is fitted to its refused extent, so the halves fill the booth face height", () => {
  const [k, dx, dy] = sealFit(66, 54);
  expect(SEAL_BOUNDS).toEqual({ minX: 16, minY: 16, maxX: 240, maxY: 240 });
  expect(k).toBeCloseTo(54 / 224);
  expect(SEAL_BOUNDS.minY * k + dy).toBeCloseTo(0);
  expect(SEAL_BOUNDS.maxY * k + dy).toBeCloseTo(54);
  expect((SEAL_BOUNDS.minX + SEAL_BOUNDS.maxX) / 2 * k + dx).toBeCloseTo(33);
});

test("no seal pose leaves the fitted box, the refusal's shake included", () => {
  for (const state of ["wait", "verify", "deny"] as const) {
    for (let ms = 0; ms <= 400; ms += 10) {
      const { gap, shakeX } = sealPose(state, ms);
      expect([32 - gap, 224 + gap, 32 + shakeX, 224 + shakeX].every((v) => v >= 16 && v <= 240)).toBe(true);
    }
  }
});

test("the Rive seal gets the same framing as the 256 artboard's destination box", () => {
  const [k, dx, dy] = sealFit(198, 162);
  expect(sealFrame(198, 162)).toEqual({ minX: dx, minY: dy, maxX: dx + 256 * k, maxY: dy + 256 * k });
});
