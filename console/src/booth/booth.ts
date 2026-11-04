import type { SealInput } from "../scene/cues";

export interface SealEngine {
  readonly name: "rive" | "canvas";
  fire(input: SealInput): void;
}

/** The booth element mirrors the state the seal engine reports. */
export class Booth {
  private engine: SealEngine | null = null;
  private current: SealInput = "wait";

  constructor(private readonly host: HTMLElement) {
    host.dataset.seal = "wait";
  }

  /** Hands the verdict to a new engine, replaying a non-wait input already set. */
  adopt(engine: SealEngine): void {
    this.engine = engine;
    this.host.dataset.sealEngine = engine.name;
    if (this.current !== "wait") engine.fire(this.current);
  }

  set(input: SealInput): void {
    if (input === this.current) return;
    this.current = input;
    this.engine?.fire(input);
  }

  report(state: string): void {
    this.host.dataset.seal = state;
  }
}
