import type { ConsoleLine } from "../wire/types";

type Listener = (lines: readonly ConsoleLine[]) => void;

/** Bounded, seq-ordered set of console lines. */
export class LineStore {
  private items: readonly ConsoleLine[] = Object.freeze([]);
  private readonly listeners = new Set<Listener>();

  constructor(private readonly max = 2000) {}

  add(line: ConsoleLine): boolean {
    let lo = 0;
    let hi = this.items.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if ((this.items[mid] as ConsoleLine).seq < line.seq) lo = mid + 1;
      else hi = mid;
    }
    if (this.items[lo]?.seq === line.seq) return false;
    if (lo === 0 && this.items.length >= this.max) return false;
    const next = [...this.items.slice(0, lo), Object.freeze(line), ...this.items.slice(lo)];
    if (next.length > this.max) next.shift();
    this.items = Object.freeze(next);
    this.notify();
    return true;
  }

  get(seq: number): ConsoleLine | undefined {
    let lo = 0;
    let hi = this.items.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const item = this.items[mid] as ConsoleLine;
      if (item.seq === seq) return item;
      if (item.seq < seq) lo = mid + 1;
      else hi = mid - 1;
    }
    return undefined;
  }

  lines(): readonly ConsoleLine[] {
    return this.items;
  }

  reset(): void {
    this.items = Object.freeze([]);
    this.notify();
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    for (const listener of this.listeners) listener(this.items);
  }
}
