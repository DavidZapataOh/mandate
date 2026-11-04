import { ApprovalError, readConsent, type ConsentFields } from "./consent";

export interface PendingQuote {
  quote_id: string;
  consent: ConsentFields;
}

export interface DeviceState {
  paired: boolean;
  fingerprint: string | null;
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
  const keys = state === null ? [] : Object.keys(state).filter((k) => k !== "voice").sort();
  const voiceOk = state === null || !("voice" in state) || typeof state.voice === "boolean";
  const shapeOk =
    voiceOk && keys.length === 2 && keys[0] === "fingerprint" && keys[1] === "paired";
  if (state !== null && shapeOk) {
    const { paired, fingerprint } = state;
    if (paired === false && fingerprint === null) return { paired, fingerprint };
    if (
      paired === true &&
      typeof fingerprint === "string" &&
      /^[0-9a-f]{16}$/.test(fingerprint)
    ) {
      return { paired, fingerprint };
    }
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
