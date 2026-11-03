import { describe, expect, it, vi } from "vitest";
import { ATTACK, CONFIRM, patch } from "./__fixtures__/lines";
import { connectLive, type EventSourceLike, RETRY_MS, type StreamState } from "./client";
import type { ConsoleLine } from "./types";

// Test double for the browser EventSource: records the URL, lets the test fire events.
class FakeSource implements EventSourceLike {
  readyState = 0;
  closed = false;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  private hello: ((event: MessageEvent<string>) => void) | null = null;

  constructor(readonly url: string) {}

  addEventListener(_type: "hello", listener: (event: MessageEvent<string>) => void): void {
    this.hello = listener;
  }

  close(): void {
    this.closed = true;
    this.readyState = 2;
  }

  open(): void {
    this.readyState = 1;
    this.onopen?.(new Event("open"));
  }

  greet(epoch: string, last = 0): void {
    this.hello?.(new MessageEvent("hello", { data: JSON.stringify({ epoch, last_seq: last }) }));
  }

  send(data: string): void {
    this.onmessage?.(new MessageEvent("message", { data }));
  }

  fail(readyState: number): void {
    this.readyState = readyState;
    this.onerror?.(new Event("error"));
  }
}

const patchedSeq = (seq: number) => patch(ATTACK, { seq });

function harness() {
  const sources: FakeSource[] = [];
  const lines: ConsoleLine[] = [];
  const states: StreamState[] = [];
  const rejected: string[] = [];
  const timers: Array<[() => void, number]> = [];
  let resets = 0;
  const client = connectLive({
    onLine: (line) => lines.push(line),
    onState: (state) => states.push(state),
    onReset: () => {
      resets += 1;
    },
    onReject: (text) => rejected.push(text),
    open: (url) => {
      const source = new FakeSource(url);
      sources.push(source);
      return source;
    },
    schedule: (run, ms) => timers.push([run, ms]),
  });
  return { client, sources, lines, states, rejected, timers, resets: () => resets };
}

describe("connectLive", () => {
  it("opens from zero and reports live", () => {
    const h = harness();
    h.sources[0]!.open();
    expect(h.sources.map((s) => s.url)).toEqual(["/api/events?since=0"]);
    expect(h.states).toEqual(["live"]);
  });

  it("delivers parsed lines and drops malformed ones", () => {
    const h = harness();
    h.sources[0]!.send(ATTACK);
    h.sources[0]!.send('{"v":3}');
    expect(h.lines.map((l) => l.seq)).toEqual([4]);
    expect(h.rejected).toEqual(['{"v":3}']);
  });

  it("resumes after the last seq once the browser gives up", () => {
    const h = harness();
    h.sources[0]!.greet("e1");
    h.sources[0]!.send(ATTACK);
    h.sources[0]!.send(CONFIRM);
    h.sources[0]!.fail(2);
    expect(h.states).toEqual(["reconnecting"]);
    expect(h.timers.map(([, ms]) => ms)).toEqual([RETRY_MS]);
    h.timers[0]![0]();
    expect(h.sources.map((s) => s.url)).toEqual([
      "/api/events?since=0",
      "/api/events?since=4",
    ]);
  });

  it("leaves a transient error to the browser's own reconnect", () => {
    const h = harness();
    h.sources[0]!.fail(0);
    expect(h.states).toEqual(["reconnecting"]);
    expect(h.timers).toEqual([]);
    expect(h.sources).toHaveLength(1);
  });

  it("starts over from zero when the server has a new epoch", () => {
    const h = harness();
    h.sources[0]!.greet("e1");
    h.sources[0]!.send(ATTACK);
    h.sources[0]!.greet("e2");
    expect(h.resets()).toBe(1);
    expect(h.sources[0]!.closed).toBe(true);
    expect(h.sources.map((s) => s.url)).toEqual([
      "/api/events?since=0",
      "/api/events?since=0",
    ]);
    h.sources[1]!.greet("e2");
    expect(h.resets()).toBe(1);
  });

  it("stops reconnecting after close", () => {
    const h = harness();
    h.client.close();
    h.sources[0]!.fail(2);
    expect(h.sources[0]!.closed).toBe(true);
    expect(h.timers).toEqual([]);
  });
  it("schedules at most one reopen however many errors arrive", () => {
    const h = harness();
    for (let i = 0; i < 5; i += 1) h.sources[0]!.fail(2);
    expect(h.timers).toHaveLength(1);
    h.timers[0]![0]();
    expect(h.sources).toHaveLength(2);
  });

  it("closes the current source and cancels a pending reopen on close", () => {
    const h = harness();
    h.sources[0]!.fail(2);
    h.client.close();
    h.timers[0]![0]();
    expect(h.sources).toHaveLength(1);
    expect(h.sources.every((s) => s.closed)).toBe(true);
  });

  it("ignores events from a superseded source", () => {
    const h = harness();
    h.sources[0]!.greet("e1");
    h.sources[0]!.greet("e2");
    h.sources[0]!.send(patchedSeq(99));
    h.sources[0]!.fail(2);
    expect(h.lines).toEqual([]);
    expect(h.states).toEqual([]);
    expect(h.timers).toEqual([]);
    h.sources[1]!.fail(2);
    h.timers[0]![0]();
    expect(h.sources.map((s) => s.url).at(-1)).toBe("/api/events?since=0");
  });

  it("keeps consumer errors apart from malformed lines", () => {
    const queued: Array<() => void> = [];
    const spy = vi.spyOn(globalThis, "queueMicrotask").mockImplementation((run) => {
      queued.push(run);
    });
    const rejected: string[] = [];
    const sources: FakeSource[] = [];
    connectLive({
      onLine: () => {
        throw new Error("consumer");
      },
      onState: () => {},
      onReset: () => {},
      onReject: (text) => rejected.push(text),
      open: (url) => {
        const source = new FakeSource(url);
        sources.push(source);
        return source;
      },
      schedule: () => {},
    });
    sources[0]!.send(ATTACK);
    spy.mockRestore();
    expect(rejected).toEqual([]);
    expect(queued).toHaveLength(1);
    expect(queued[0]).toThrow("consumer");
    sources[0]!.fail(2);
  });

  it("advances the resume point only for lines that parse", () => {
    const h = harness();
    h.sources[0]!.send('{"v":3,"seq":50}');
    h.sources[0]!.send(ATTACK);
    h.sources[0]!.fail(2);
    h.timers[0]![0]();
    expect(h.sources.at(-1)!.url).toBe("/api/events?since=4");
  });
});
