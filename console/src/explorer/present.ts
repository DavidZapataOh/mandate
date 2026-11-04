import type { Receipt } from "./receipt";
import { readDisclosure } from "./sdjwt";
import { GROUPS, type Group } from "./verify";

const FIELD_GROUPS: readonly Group[] = ["amount", "payee", "account", "reference"];
// Each opens every hidden field, so it travels only with all four field groups.
const FULL = ["targets", "action_salt", "signature"];

/** The receipt keeping only the Disclosures of the revealed groups; the gate-signed JWT is untouched. */
export function presentation(r: Receipt, reveal: ReadonlySet<Group>): Receipt {
  const names = new Set<string>([...reveal].flatMap((group) => GROUPS[group]));
  if (FIELD_GROUPS.every((group) => reveal.has(group))) for (const name of FULL) names.add(name);
  const [token, ...rest] = r.sd.split("~");
  const kept = rest.slice(0, -1).filter((d) => names.has(readDisclosure(d)?.name ?? ""));
  return { ...r, sd: [token, ...kept, ""].join("~") };
}
