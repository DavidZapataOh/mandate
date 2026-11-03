import { parseLine, WireError } from "./parse";
import type { ConsoleLine } from "./types";

export const REPLAY_STEP_MS = 600;

const NAME = /^[a-z0-9-]{1,40}$/;

type Schedule = (run: () => void, ms: number) => void;

/** The recording named by `?replay=`, or null in live mode; unsafe names throw. */
export function replayName(search: string): string | null {
  const name = new URLSearchParams(search).get("replay");
  if (name === null) return null;
  if (!NAME.test(name)) throw new WireError("wire: bad replay name");
  return name;
}

/** Parse a recorded stream (one v3 line per row); one bad or out-of-order line rejects it all. */
export function parseRecording(text: string): ConsoleLine[] {
  const lines: ConsoleLine[] = [];
  text.split("\n").forEach((raw, index) => {
    if (raw.trim() === "") return;
    let line: ConsoleLine;
    try {
      line = parseLine(raw);
    } catch {
      throw new WireError(`wire: replay line ${index + 1} malformed`);
    }
    // A second process appending to the same capture numbers from 1 again.
    const previous = lines.at(-1);
    if (previous !== undefined && line.seq <= previous.seq) {
      throw new WireError(`wire: replay line ${index + 1} out of order`);
    }
    lines.push(line);
  });
  return lines;
}

/** Deliver the first line at once, then one every `stepMs`, in recorded order. */
export function playRecording(
  lines: readonly ConsoleLine[],
  onLine: (line: ConsoleLine) => void,
  schedule: Schedule = (run, ms) => void setTimeout(run, ms),
  stepMs: number = REPLAY_STEP_MS,
): void {
  const play = (index: number): void => {
    const line = lines[index];
    if (line === undefined) return;
    try {
      onLine(line);
    } catch (error) {
      queueMicrotask(() => {
        throw error;
      });
    }
    schedule(() => play(index + 1), stepMs);
  };
  play(0);
}
