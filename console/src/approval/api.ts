import { ApprovalError, readConsent, type ConsentFields } from "./consent";

/** The most holder devices one desk pairs. */
const MAX_HOLDERS = 16;

export interface PendingQuote {
  quote_id: string;
  consent: ConsentFields;
}

/** How many holder devices are paired; the desk never names one. */
export interface DeviceState {
  holders: number;
}

export interface DeskApi {
  pending(): Promise<PendingQuote[]>;
  device(): Promise<DeviceState>;
}

async function get(fetchFn: typeof fetch, path: string): Promise<unknown> {
  const response = await fetchFn(path, { headers: { accept: "application/json" } });
  if (!response.ok) {
    throw new ApprovalError(`approval: desk answered ${response.status}`);
  }
  return response.json();
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function readPending(body: unknown): PendingQuote[] {
  const list = record(body)?.pending;
  if (!Array.isArray(list)) throw new ApprovalError("approval: malformed pending list");
  return list.map((item) => {
    const quote = record(item);
    if (typeof quote?.quote_id !== "string") {
      throw new ApprovalError("approval: malformed pending list");
    }
    return { quote_id: quote.quote_id, consent: readConsent(quote.consent) };
  });
}

function readDevice(body: unknown): DeviceState {
  const state = record(body);
  // `voice` belongs to the holder page; the console reads and ignores it.
  const keys = state === null ? [] : Object.keys(state).filter((k) => k !== "voice");
  const voiceOk = state === null || !("voice" in state) || typeof state.voice === "boolean";
  const holders = state?.holders;
  if (
    voiceOk &&
    keys.length === 1 &&
    keys[0] === "holders" &&
    typeof holders === "number" &&
    Number.isSafeInteger(holders) &&
    holders >= 0 &&
    holders <= MAX_HOLDERS
  ) {
    return { holders };
  }
  throw new ApprovalError("approval: malformed device state");
}

/** Reads the desk's pending quotes and holder device state over GET only. */
export function httpDesk(
  fetchFn: typeof fetch = (input, init) => fetch(input, init),
): DeskApi {
  return {
    pending: async () => readPending(await get(fetchFn, "/api/pending")),
    device: async () => readDevice(await get(fetchFn, "/api/device")),
  };
}
