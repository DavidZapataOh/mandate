import { describe, expect, it } from "vitest";
import { ATTACK, BANK, CONFIRM, patch, SANDBOX_CONFIRM } from "./__fixtures__/lines";
import { parseLine } from "./parse";
import { railOf } from "./rail";

describe("railOf", () => {
  it.each([
    ["a simulated desk payment", CONFIRM, "simulated"],
    ["a sandbox desk payment", SANDBOX_CONFIRM, "sandbox"],
    ["a refused attack", ATTACK, null],
    ["what the bank reported", BANK, "sandbox"],
    ["a quote", patch(CONFIRM, { forensic: null, event: null }, { step: "quote" }), null],
  ])("%s", (_, text, rail) => {
    expect(railOf(parseLine(text))).toBe(rail);
  });
});
