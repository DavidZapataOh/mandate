import { expect, test } from "vitest";
import { FixedLoop } from "./loop";
import { ManualClock } from "./__fixtures__/manual-clock";

function harness() {
  const clock = new ManualClock();
  const steps: number[] = [];
  let renders = 0;
  const loop = new FixedLoop(clock, { step: (dt) => steps.push(dt), render: () => renders++ });
  return { clock, loop, steps, renders: () => renders };
}

test("first tick only renders; elapsed time becomes whole 16 ms steps", () => {
  const h = harness();
  expect(h.loop.tick()).toBe(0);
  h.clock.advance(48);
  expect(h.loop.tick()).toBe(3);
  h.clock.advance(52);
  expect(h.loop.tick()).toBe(3);
  h.clock.advance(12);
  expect(h.loop.tick()).toBe(1);
  expect(h.steps).toEqual([16, 16, 16, 16, 16, 16, 16]);
  expect(h.renders()).toBe(4);
});

test("a long stall runs at most 8 steps and drops the backlog", () => {
  const h = harness();
  h.loop.tick();
  h.clock.advance(1000);
  expect(h.loop.tick()).toBe(8);
  h.clock.advance(16);
  expect(h.loop.tick()).toBe(1);
});

test("two loops fed the same clock readings step identically", () => {
  const readings = [0, 7, 33, 34, 90, 91, 400];
  const run = () => {
    const h = harness();
    let last = 0;
    return readings.map((t) => {
      h.clock.advance(t - last);
      last = t;
      return h.loop.tick();
    });
  };
  expect(run()).toEqual([0, 0, 2, 0, 3, 0, 8]);
  expect(run()).toEqual(run());
});

test("start schedules the next frame after every tick", () => {
  const h = harness();
  const queue: (() => void)[] = [];
  h.loop.start((cb) => queue.push(cb));
  h.clock.advance(16);
  queue.shift()!();
  h.clock.advance(16);
  queue.shift()!();
  expect(h.steps).toEqual([16]);
  expect(queue).toHaveLength(1);
});
