/** The page's only network access: same-origin GETs, cancelled through `signal` when they take too long. */
export type Fetch = (url: string, init?: { signal?: AbortSignal }) => Promise<Response>;

/** The keys this server publishes (standard base64). */
export interface PublishedKeys {
  gateKey: string;
  holderKeys: string[];
}

/** How long a request may take before the server counts as unreachable. */
export const TIMEOUT_MS = 10_000;

async function body(fetchFn: Fetch, url: string): Promise<{ status: number; value: unknown } | null> {
  const abort = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  // The timer settles the wait even when a fetch ignores the signal.
  const expired = new Promise<null>((resolve) => {
    timer = setTimeout(() => {
      abort.abort();
      resolve(null);
    }, TIMEOUT_MS);
  });
  const answer = async () => {
    const response = await fetchFn(url, { signal: abort.signal });
    if (response.status !== 200) return { status: response.status, value: undefined };
    return { status: 200, value: (await response.json()) as unknown };
  };
  try {
    return await Promise.race([answer(), expired]);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** The published gate and holder keys, or null when the server is unreachable or answers anything else. */
export async function fetchKeys(fetchFn: Fetch): Promise<PublishedKeys | null> {
  const got = await body(fetchFn, "/api/keys");
  if (got === null || got.status !== 200) return null;
  const value = got.value;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const keys = Object.keys(value);
  const { gate_key, holder_keys } = value as Record<string, unknown>;
  if (keys.length !== 2 || !keys.includes("gate_key") || !keys.includes("holder_keys")) return null;
  if (typeof gate_key !== "string" || !Array.isArray(holder_keys) || !holder_keys.every((k) => typeof k === "string")) {
    return null;
  }
  return { gateKey: gate_key, holderKeys: holder_keys as string[] };
}

/**
 * The stored receipt of a payment: the auditor copy, or the holder copy when `full`. A 403 is the holder copy
 * refused off the desk's own machine; anything else but 200 or 404 counts as the server being unreachable.
 */
export async function fetchReceipt(
  id: string,
  fetchFn: Fetch,
  full = false,
): Promise<{ value: unknown } | "not found" | "local only" | "offline"> {
  const got = await body(fetchFn, `/api/receipt/${encodeURIComponent(id)}${full ? "?disclose=all" : ""}`);
  if (got === null) return "offline";
  if (got.status === 200) return { value: got.value };
  if (got.status === 404) return "not found";
  if (got.status === 403 && full) return "local only";
  return "offline";
}
