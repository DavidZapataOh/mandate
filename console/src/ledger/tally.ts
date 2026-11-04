import { cueFor } from "../scene/cues";
import { formatLatency } from "../shared/format";
import type { ConsoleLine } from "../wire/types";

export interface Tally {
  verified: number;
  denied: number;
  p50: string;
}

/** Counters for the top bar: verified, denied, and the lower median gate latency. */
export function tally(lines: readonly ConsoleLine[]): Tally {
  let verified = 0;
  let denied = 0;
  const latencies: number[] = [];
  for (const line of lines) {
    const { outcome } = cueFor(line);
    if (outcome === "pass") verified += 1;
    else if (outcome === "deny") denied += 1;
    if (line.event) latencies.push(line.event.lat_us);
  }
  latencies.sort((a, b) => a - b);
  const median = latencies[Math.floor((latencies.length - 1) / 2)];
  return { verified, denied, p50: median === undefined ? "—" : formatLatency(median) };
}
