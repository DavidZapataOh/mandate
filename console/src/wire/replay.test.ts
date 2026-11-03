import { describe, expect, it, vi } from "vitest";
import { ATTACK, CONFIRM } from "./__fixtures__/lines";
import { parseRecording, playRecording, replayName } from "./replay";
import type { ConsoleLine } from "./types";

describe("replayName", () => {
  it("reads a safe recording name", () => {
    expect(replayName("?replay=demo-1")).toBe("demo-1");
    expect(replayName("?mode=x")).toBeNull();
  });

  it.each(["?replay=", "?replay=../secrets", "?replay=https://evil.example/x", "?replay=Demo"])(
    "refuses %s",
    (search) => {
      expect(() => replayName(search)).toThrow("wire: bad replay name");
    },
  );
});

describe("parseRecording", () => {
  it("reads every recorded line in order", () => {
    const lines = parseRecording(`${CONFIRM}\n${ATTACK}\n\n`);
    expect(lines.map((l) => l.seq)).toEqual([3, 4]);
  });

  it("rejects the whole recording on one bad line", () => {
    expect(() => parseRecording(`${CONFIRM}\n{"v":3}\n`)).toThrow("wire: replay line 2 malformed");
  });

  it("rejects a recording that restarts its numbering", () => {
    expect(() => parseRecording(`${CONFIRM}\n${ATTACK}\n\n${CONFIRM}\n`)).toThrow(
      "wire: replay line 4 out of order",
    );
    expect(() => parseRecording(`${ATTACK}\n${ATTACK}`)).toThrow(
      "wire: replay line 2 out of order",
    );
  });
});

describe("playRecording", () => {
  it("plays one line per step in recorded order", () => {
    const seen: number[] = [];
    const timers: Array<[() => void, number]> = [];
    const lines = parseRecording(`${CONFIRM}\n${ATTACK}`);
    playRecording(lines, (line: ConsoleLine) => seen.push(line.seq), (run, ms) => {
      timers.push([run, ms]);
    });
    expect(seen).toEqual([3]);
    expect(timers.map(([, ms]) => ms)).toEqual([600]);
    timers.shift()![0]();
    expect(seen).toEqual([3, 4]);
    timers.shift()![0]();
    expect(seen).toEqual([3, 4]);
    expect(timers).toEqual([]);
  });

  it("keeps playing when a listener throws", () => {
    const queued: Array<() => void> = [];
    const spy = vi.spyOn(globalThis, "queueMicrotask").mockImplementation((run) => {
      queued.push(run);
    });
    const seen: number[] = [];
    const timers: Array<() => void> = [];
    playRecording(
      parseRecording(`${CONFIRM}\n${ATTACK}`),
      (line) => {
        seen.push(line.seq);
        throw new Error("listener");
      },
      (run) => void timers.push(run),
    );
    timers.shift()!();
    spy.mockRestore();
    expect(seen).toEqual([3, 4]);
    expect(queued).toHaveLength(2);
    expect(queued[0]).toThrow("listener");
  });
});
