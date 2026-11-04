import { rawKey, toBase64 } from "./bytes";
import type { Disclosed, Receipt } from "./receipt";

/** What no receipt carries, whatever the holder discloses. */
export const NEVER_IN_A_RECEIPT = [
  "The gate's or the holder's private keys",
  "Account balances",
  "The bill behind the payment",
  "The model's reasoning in clear (only its commitment or encrypted blobs)",
  "The bank API key",
  "Your bank balance",
] as const;

/** How many holder keys the server publishes, as the set a receipt's reader cannot tell apart; the issuing gate can. */
export function anonymityText(holderKeys: readonly string[] | null): string {
  if (holderKeys === null) return "Anonymity set unknown: this page has no holder list from the server.";
  const distinct = new Set<string>();
  for (const text of holderKeys) {
    const key = rawKey(text);
    if (key !== null) distinct.add(toBase64(key));
  }
  const n = distinct.size;
  if (n === 0) return "Anonymity set: no holder has paired with this server yet.";
  if (n === 1) return "Anonymity set: 1 holder key. Every receipt this server issued was approved by that one holder.";
  return `Anonymity set: ${n} holder keys. A receipt's consent key is used once and names none of them, so a reader cannot tell which holder approved it; the issuing gate can.`;
}

/** How a field the holder did not disclose reads. */
export const WITHHELD = "Withheld (a salted digest in the gate-signed receipt)";

function money(cents: number, currency: string): string {
  const abs = Math.abs(cents);
  const sign = cents < 0 ? "-" : "";
  return `${sign}${Math.floor(abs / 100)}.${String(abs % 100).padStart(2, "0")} ${currency}`;
}

const or = (value: string | undefined) => value ?? WITHHELD;

/** What a verified receipt shows its reader, field by field; a concealed field reads WITHHELD. */
export function exposure(r: Receipt, d: Disclosed): Array<[string, string]> {
  const c = d.consent;
  const amount = c.amount_cents === undefined || c.currency === undefined ? undefined : money(c.amount_cents, c.currency);
  const rows: Array<[string, string]> = [
    ["Amount", or(amount)],
    ["Payee account", or(c.recipient)],
    ["Debit account", or(c.source)],
    ["Reference", or(c.reference)],
    ["Payment and quote ids", [d.sub, ...d.cava.evidence_refs].join(", ")],
    ["Consent key (this payment only)", c.consent_key],
    ["Holder public key", or(c.holder_key)],
    ["Sealed at (unix seconds)", String(r.registry.seal.ts)],
  ];
  if (d.bank !== null) {
    const { rail, provider, transfer_id, status } = d.bank;
    rows.push(["Bank transfer", `${rail.toUpperCase()} ${provider === null ? "" : `${provider} `}${transfer_id} (${status})`]);
  }
  if (d.funds !== null) rows.push(["Funds proof", `${d.funds.kind.toUpperCase()} ${d.funds.evidence_ref}`]);
  if (r.reasoning !== null) {
    rows.push(["Encrypted model reasoning", `${r.reasoning.blobs.length} blob(s) from ${r.reasoning.model}`]);
  }
  return rows;
}
