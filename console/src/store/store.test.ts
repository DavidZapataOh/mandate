import { describe, expect, it } from "vitest";
import { ATTACK, patch } from "../wire/__fixtures__/lines";
import { parseLine } from "../wire/parse";
import { LineStore } from "./store";

const at = (seq: number) => parseLine(patch(ATTACK, { seq }));
const seqs = (store: LineStore) => store.lines().map((line) => line.seq);

describe("LineStore", () => {
  it("keeps lines in seq order whatever the arrival order", () => {
    const store = new LineStore();
    for (const seq of [3, 1, 2]) store.add(at(seq));
    expect(seqs(store)).toEqual([1, 2, 3]);
  });

  it("holds each seq once", () => {
    const store = new LineStore();
    expect(store.add(at(2))).toBe(true);
    expect(store.add(at(2))).toBe(false);
    expect(seqs(store)).toEqual([2]);
  });

  it("keeps only the newest max lines", () => {
    const store = new LineStore(2);
    for (const seq of [1, 2, 3]) store.add(at(seq));
    expect(seqs(store)).toEqual([2, 3]);
    expect(store.add(at(1))).toBe(false);
    expect(store.get(1)).toBeUndefined();
    expect(store.get(3)?.seq).toBe(3);
  });

  it("notifies on add and reset until unsubscribed", () => {
    const store = new LineStore();
    const seen: number[] = [];
    const stop = store.subscribe((lines) => seen.push(lines.length));
    store.add(at(1));
    store.add(at(1));
    store.reset();
    stop();
    store.add(at(2));
    expect(seen).toEqual([1, 0]);
    expect(seqs(store)).toEqual([2]);
  });
  it("hands out frozen snapshots that later adds never change", () => {
    const store = new LineStore();
    store.add(at(1));
    const held = store.lines();
    store.add(at(2));
    expect(held).toHaveLength(1);
    expect(store.lines()).toHaveLength(2);
    expect(() => {
      (held as unknown as unknown[]).length = 0;
    }).toThrow();
    expect(() => {
      (store.lines() as unknown as unknown[]).length = 0;
    }).toThrow();
    expect(seqs(store)).toEqual([1, 2]);
    expect(Object.isFrozen(store.get(1))).toBe(true);
  });

  it("passes subscribers the same frozen snapshot", () => {
    const store = new LineStore();
    let seen: readonly unknown[] = [];
    store.subscribe((lines) => {
      seen = lines;
    });
    store.add(at(1));
    expect(Object.isFrozen(seen)).toBe(true);
    expect(seen).toBe(store.lines());
  });
});
