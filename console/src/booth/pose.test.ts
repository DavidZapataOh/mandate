import { expect, test } from "vitest";
import { sealPose } from "./pose";

test.each([
  ["wait", 0, { gap: 8, shakeX: 0, seam: "none" }],
  ["verify", 0, { gap: 8, shakeX: 0, seam: "verify" }],
  ["verify", 66.5, { gap: 4, shakeX: 0, seam: "verify" }],
  ["verify", 133, { gap: 0, shakeX: 0, seam: "verify" }],
  ["verify", 5000, { gap: 0, shakeX: 0, seam: "verify" }],
  ["deny", 0, { gap: 8, shakeX: -6, seam: "alert" }],
  ["deny", 50, { gap: 12, shakeX: -6, seam: "alert" }],
  ["deny", 80, { gap: 14.4, shakeX: 6, seam: "alert" }],
  ["deny", 250, { gap: 16, shakeX: 6, seam: "alert" }],
  ["deny", 320, { gap: 16, shakeX: 0, seam: "alert" }],
] as const)("sealPose(%s, %f): halves snap shut with no bounce or refuse to meet", (state, ms, want) => {
  expect(sealPose(state, ms)).toEqual(want);
});
