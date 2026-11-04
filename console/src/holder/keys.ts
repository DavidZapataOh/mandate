/** Where this device keeps its holder key pair. */
export interface KeyStore {
  load(): Promise<CryptoKeyPair | null>;
  save(pair: CryptoKeyPair): Promise<void>;
}

/** This device's holder key: made once, its private half not extractable. */
export async function holderKey(store: KeyStore): Promise<CryptoKeyPair> {
  const saved = await store.load();
  if (saved) return saved;
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
  await store.save(pair);
  return pair;
}

// The same slot the `/app/` page uses, so one pairing serves both pages.
const DB = "mandate-holder";
const STORE = "keys";
const SLOT = "holder";

function idbRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/** The browser's IndexedDB slot for the holder key. */
export async function indexedDbStore(): Promise<KeyStore> {
  const open = indexedDB.open(DB, 1);
  open.onupgradeneeded = () => open.result.createObjectStore(STORE);
  const db = await idbRequest(open);
  const objects = (mode: IDBTransactionMode) => db.transaction(STORE, mode).objectStore(STORE);
  return {
    load: async () => ((await idbRequest(objects("readonly").get(SLOT))) as CryptoKeyPair | undefined) ?? null,
    save: async (pair) => {
      await idbRequest(objects("readwrite").put(pair, SLOT));
    },
  };
}

/**
 * Registers the holder key when the URL fragment carries the desk's pairing
 * token. Returns a status line, or null when there is nothing to pair.
 */
export async function pairHolder(
  publicKey: string,
  hash: string,
  register: (publicKey: string, pairing: string) => Promise<{ registered: boolean }>,
): Promise<string | null> {
  const token = new URLSearchParams(hash.replace(/^#/, "")).get("pair");
  if (!token) return null;
  const { registered } = await register(publicKey, token);
  return registered
    ? "Paired with the desk."
    : "Another holder is already paired; intents from this device will be refused.";
}
