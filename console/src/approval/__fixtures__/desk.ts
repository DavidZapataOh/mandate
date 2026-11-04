import { CONFIRM, patch } from "../../wire/__fixtures__/lines";
import { parseLine } from "../../wire/parse";
import type { ConsoleLine, DeskSubject } from "../../wire/types";
import type { ConsentFields } from "../consent";

/** The consent the CONFIRM fixture's gate run checked. */
export const FIELDS: ConsentFields = {
  amount_cents: 20000,
  currency: "USD",
  expires_at: 1800001600,
  nonce: "00000000000000000000000000000001",
  recipient: "acme-991",
  reference: "A-991",
  source: "checking-881",
};
export const FIELDS_HASH =
  "2c34f3c4 7a473eaa 1454ed99 bc724676 b0e16531 637192d4 1257bc28 d2f5cd54";
export const SUMMARY =
  "MANDATE_FIXTURE Pay 1.00 USD to friend-001 (ref X-1) from checking-881";

/** A desk line; only confirm lines keep the CONFIRM fixture's gate run. */
export function desk(
  seq: number,
  step: DeskSubject["step"],
  status: string,
  subject: Partial<DeskSubject> = {},
  top: Record<string, unknown> = {},
): ConsoleLine {
  const gate = step === "confirm" ? {} : { event: null, forensic: null };
  return parseLine(
    patch(
      CONFIRM,
      { seq, ...gate, ...top },
      {
        step,
        status,
        quote_id: "q:000001",
        payment_id: null,
        reason: null,
        summary: SUMMARY,
        ...subject,
      },
    ),
  );
}

/** The CONFIRM fixture's forensic block with its consent replaced. */
export function checked(consent: ConsentFields): Record<string, unknown> {
  return { forensic: { ...JSON.parse(CONFIRM).forensic, consent } };
}
