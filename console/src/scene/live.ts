import type { ConsoleLine } from "../wire/types";

/** Picks the lines worth animating: only those published after the stream opened. */
export class LiveCues {
  private watermark = 0;

  /** Lines up to `lastSeq` were already on the server; they fill the ledger silently. */
  hello(lastSeq: number): void {
    this.watermark = Math.max(this.watermark, lastSeq);
  }

  take(lines: readonly ConsoleLine[]): ConsoleLine[] {
    if (lines.length === 0) {
      this.watermark = 0;
      return [];
    }
    const fresh: ConsoleLine[] = [];
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i] as ConsoleLine;
      if (line.seq <= this.watermark) break;
      fresh.push(line);
    }
    fresh.reverse();
    const last = fresh.at(-1);
    if (last) this.watermark = last.seq;
    return fresh;
  }
}
