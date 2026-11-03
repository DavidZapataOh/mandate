/** Format a latency given in microseconds. */
export function formatLatency(us: number): string {
  return us < 1000 ? `${Math.round(us)}µs` : `${(us / 1000).toFixed(1)}ms`;
}
