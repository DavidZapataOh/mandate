export const STEP_MS = 16;
export const MAX_STEPS = 8;

export interface Clock {
  now(): number;
}

export const performanceClock: Clock = { now: () => performance.now() };

export interface LoopHooks {
  step(dtMs: number): void;
  render(): void;
}

export class FixedLoop {
  private last: number | null = null;
  private acc = 0;
  private handle: number | null = null;
  private running = false;

  constructor(
    private readonly clock: Clock,
    private readonly hooks: LoopHooks,
  ) {}

  tick(): number {
    const now = this.clock.now();
    if (this.last !== null) this.acc += now - this.last;
    this.last = now;
    let steps = 0;
    while (this.acc >= STEP_MS && steps < MAX_STEPS) {
      this.hooks.step(STEP_MS);
      this.acc -= STEP_MS;
      steps++;
    }
    // A stall must not be replayed as a burst of catch-up frames.
    if (this.acc >= STEP_MS) this.acc = 0;
    this.hooks.render();
    return steps;
  }

  start(schedule: (cb: () => void) => number = (cb) => requestAnimationFrame(cb)): void {
    this.running = true;
    const frame = (): void => {
      if (!this.running) return;
      this.tick();
      if (this.running) this.handle = schedule(frame);
    };
    this.handle = schedule(frame);
  }

  stop(cancel: (h: number) => void = (h) => cancelAnimationFrame(h)): void {
    this.running = false;
    if (this.handle !== null) cancel(this.handle);
    this.handle = null;
  }
}
