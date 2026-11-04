import type { ConsoleLine, Rail } from "./types";

export const RAIL_LABEL: Readonly<Record<Rail, string>> = { simulated: "SIMULATED", sandbox: "SANDBOX" };

/** The bank rail that moved a line's money or reported it, or null when no bank record rides on it. */
export function railOf(line: ConsoleLine): Rail | null {
  if (line.source === "bank") return line.subject.rail;
  return line.forensic?.bank?.rail ?? null;
}
