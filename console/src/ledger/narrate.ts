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
