import { expect, test } from "vitest";
import { attack, confirmed, desk, gateEvent, hook } from "../scene/__fixtures__/cases";
import { HOSTILE } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { tally } from "./tally";

test("no lines: nothing verified, nothing denied, no latency to report", () => {
  expect(tally([])).toEqual({ verified: 0, denied: 0, p50: "—" });
});

test("counters count verified and denied lines and report the lower median gate latency", () => {
  const lines = [
    confirmed(),
    attack("amount_inflate", "model->gate", { gate: gateEvent("NOT_MET", "amount differs from intent", 1234.5) }),
    parseLine(HOSTILE),
    hook("MET", "ok"),
    desk("quote", "quoted"),
  ];
  expect(tally(lines)).toEqual({ verified: 2, denied: 2, p50: "61µs" });
});
