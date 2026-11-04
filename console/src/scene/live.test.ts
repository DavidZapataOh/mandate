import { expect, test } from "vitest";
import { attack } from "./__fixtures__/cases";
import { LiveCues } from "./live";

const at = (...seqs: number[]) => seqs.map((seq) => attack("mcp_exfil", "mcp", { seq }));
const seqs = (lines: { seq: number }[]) => lines.map((l) => l.seq);

test("lines the server already had when the stream opened fill the ledger but do not animate", () => {
  const live = new LiveCues();
  live.hello(4);
  expect(seqs(live.take(at(3, 4)))).toEqual([]);
  expect(seqs(live.take(at(3, 4, 7)))).toEqual([7]);
});

test("a reset restarts from the new server's backlog", () => {
  const live = new LiveCues();
  live.hello(0);
  live.take(at(5, 6, 7));
  expect(live.take([])).toEqual([]);
  live.hello(2);
  expect(seqs(live.take(at(1, 2)))).toEqual([]);
  expect(seqs(live.take(at(1, 2, 3)))).toEqual([3]);
});

test("a replay has no hello, so every line plays in seq order", () => {
  expect(seqs(new LiveCues().take(at(3, 4)))).toEqual([3, 4]);
});

test("a line never animates twice, even when an older one arrives late", () => {
  const live = new LiveCues();
  live.hello(0);
  expect(seqs(live.take(at(4)))).toEqual([4]);
  expect(seqs(live.take(at(3, 4)))).toEqual([]);
  expect(seqs(live.take(at(3, 4, 5)))).toEqual([5]);
});
