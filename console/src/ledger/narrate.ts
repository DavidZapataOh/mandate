import { cueFor, deployLabel, type Outcome } from "../scene/cues";
import { formatLatency } from "../shared/format";
import type { ConsoleLine } from "../wire/types";

export type Mode = "game" | "forensic";

/** The reason a line carries, preferring the subject's own. */
export function reasonOf(line: ConsoleLine): string {
  if (line.source === "attack" || line.source === "deploy") return line.subject.reason;
  if (line.source === "desk" && line.subject.reason) return line.subject.reason;
  if (line.source === "bank") return line.subject.category;
  return line.event?.reason ?? "";
}

function deskText(line: Extract<ConsoleLine, { source: "desk" }>): string {
  const s = line.subject;
  const reason = reasonOf(line);
  if (s.step === "card") {
    // What Mandate answered the bank's question; the confirm it rides on, if any, is its own line.
    if (s.status === "approved") return `Card approved by Mandate: ${s.summary} · ${s.payment_id}`;
    if (s.status === "declined") return `Card declined by Mandate: ${reason} · ${s.payment_id}`;
    if (s.status === "not_answered") return `Card not answered by Mandate; the bank decides: ${reason} · ${s.payment_id}`;
    return `Card outcome unknown: ${reason} · ${s.payment_id}`;
  }
  if (s.step === "intent") {
    if (s.status === "signed") return `Holder signed intent: ${s.summary}`;
    if (s.status === "proven") return `Bank balance proven (zkTLS): ${s.summary}`;
    return reason.startsWith("zktls:") ? `Funds proof refused: ${reason}` : `Intent refused: ${reason}`;
  }
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
  if (s.step === "settle") {
    // An observation of the bank, after the receipt was sealed: it never reads as a payment of its own.
    return s.status === "returned"
      ? `Returned by the bank: ${s.summary} · ${s.payment_id} · ${reason}`
      : `Settled at the bank: ${s.summary} · ${s.payment_id}`;
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
    case "deploy": {
      const s = line.subject;
      if (s.step === "release" && !s.blocked) {
        return `Released ✓ ${s.summary}${line.event ? ` in ${formatLatency(line.event.lat_us)}` : ""}`;
      }
      return `${s.blocked ? "Blocked" : "NOT BLOCKED:"} ${deployLabel(s.step)} at ${s.layer}: ${s.reason}`;
    }
    case "hook": {
      const s = line.subject;
      const what = [s.tool, ...s.targets].join(" ");
      return line.event?.verdict === "MET" ? `${s.agent} allowed ${what}` : `${s.agent} denied ${what}: ${reasonOf(line)}`;
    }
    case "bill":
      return line.event?.verdict === "MET"
        ? `Bill paid ✓ ${line.subject.summary}`
        : `Bill denied: ${line.subject.summary}: ${reasonOf(line)}`;
    case "bank":
      return `Bank reports: ${line.subject.summary} · ${line.subject.object_id}`;
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
  if (line.source === "bank") return line.subject.created_at.slice(11, 19);
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
