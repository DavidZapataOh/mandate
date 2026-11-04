import { cueFor, type Outcome } from "../scene/cues";
import { formatLatency } from "../shared/format";
import type { ConsoleLine } from "../wire/types";

export type Mode = "game" | "forensic";

/** The reason a line carries, preferring the subject's own. */
export function reasonOf(line: ConsoleLine): string {
  if (line.source === "attack") return line.subject.reason;
  if (line.source === "desk" && line.subject.reason) return line.subject.reason;
  return line.event?.reason ?? "";
}

function deskText(line: Extract<ConsoleLine, { source: "desk" }>): string {
  const s = line.subject;
  const reason = reasonOf(line);
  if (s.step === "quote") {
    return s.quote_id === null || s.status !== "quoted"
      ? `Quote refused: ${reason}`
      : `Quote ${s.quote_id}: ${s.summary}`;
  }
  if (s.step === "approve") {
    return s.status === "approved"
      ? `Holder approved ${s.quote_id}`
      : `Approval of ${s.quote_id} refused: ${reason}`;
  }
  if (s.status === "confirmed") {
    const took = line.event ? ` in ${formatLatency(line.event.lat_us)}` : "";
    return `Paid ✓ ${s.summary}${took}`;
  }
  return `Payment ${s.quote_id} ${s.status}: ${reason}`;
}

/** One plain sentence per line. */
export function gameText(line: ConsoleLine): string {
  switch (line.source) {
    case "desk":
      return deskText(line);
    case "attack": {
      const what = `${line.subject.attack.replaceAll("_", " ")} at ${line.subject.layer}`;
      return line.subject.blocked
        ? `Blocked ${what}: ${line.subject.reason}`
        : `NOT BLOCKED: ${what}: ${line.subject.reason}`;
    }
    case "hook": {
      const who = line.subject.agent;
      return line.event?.verdict === "MET"
        ? `${who} ran ${line.subject.tool}`
        : `${who} denied ${line.subject.tool}: ${reasonOf(line)}`;
    }
    case "bill":
      return line.event?.verdict === "MET"
        ? `Bill paid ✓ ${line.subject.summary}`
        : `Bill denied: ${line.subject.summary}: ${reasonOf(line)}`;
  }
}

/** One dense row per line: seq, source, verdict, hash prefix, reason. */
export function forensicText(line: ConsoleLine): string {
  const hash = line.forensic?.action_hash ?? line.event?.action ?? "-";
  return `#${line.seq} ${line.source} ${line.event?.verdict ?? "-"} ${hash.slice(0, 12)} ${reasonOf(line)}`;
}

export type VerdictWord = "VERIFIED" | "DENIED" | "WAITING" | "NOT BLOCKED" | "NOTED";

export interface Cells {
  time: string;
  actor: string;
  hash: string;
  verdict: VerdictWord;
  outcome: Outcome;
  struck: boolean;
}

const VERDICTS: Record<Outcome, VerdictWord> = {
  pass: "VERIFIED",
  deny: "DENIED",
  hold: "WAITING",
  breach: "NOT BLOCKED",
  note: "NOTED",
};

const NO_TIME = "--:--:--";

// UTC so a reload shows the same time on any machine.
function clock(seconds: number): string {
  return new Date(seconds * 1000).toISOString().slice(11, 19);
}

function timeOf(line: ConsoleLine): string {
  if (line.event) return clock(line.event.ts);
  const freshness = line.forensic?.cava["freshness"];
  if (typeof freshness === "object" && freshness !== null) {
    const stamp = (freshness as Record<string, unknown>)["timestamp"];
    if (typeof stamp === "number") return clock(stamp);
  }
  return NO_TIME;
}

/** The cells of one ledger row. */
export function cellsOf(line: ConsoleLine): Cells {
  const cue = cueFor(line);
  const action = line.forensic?.action_hash ?? line.event?.action;
  return {
    time: timeOf(line),
    actor: cue.tag,
    hash: action ? action.slice(0, 6).toUpperCase() : "------",
    verdict: VERDICTS[cue.outcome],
    outcome: cue.outcome,
    struck: cue.outcome === "deny",
  };
}
