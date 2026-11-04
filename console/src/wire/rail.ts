import type { ConsoleLine, Rail } from "./types";

export const RAIL_LABEL: Readonly<Record<Rail, string>> = { simulated: "SIMULATED", sandbox: "SANDBOX" };

/** The bank rail that moved a line's money, or null when no bank record rides on it. */
export function railOf(line: ConsoleLine): Rail | null {
  return line.forensic?.bank?.rail ?? null;
}
