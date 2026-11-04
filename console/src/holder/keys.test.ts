import { describe, expect, it } from "vitest";
import { holderKey, pairHolder, type KeyStore } from "./keys";

function memory(): KeyStore & { saved: CryptoKeyPair[] } {
  const saved: CryptoKeyPair[] = [];
  return { saved, load: async () => saved[0] ?? null, save: async (pair) => void saved.push(pair) };
}

describe("holder key", () => {
  it("is made once per device with a private half that never leaves it", async () => {
    const store = memory();
    const first = await holderKey(store);
    expect(await holderKey(store)).toBe(first);
    expect([store.saved.length, first.privateKey.extractable]).toEqual([1, false]);
    await expect(crypto.subtle.exportKey("pkcs8", first.privateKey)).rejects.toThrow();
  });
});

describe("pairing", () => {
  it("spends the fragment's token once and says how it went", async () => {
    const sent: string[][] = [];
    const register = async (key: string, pairing: string) => {
      sent.push([key, pairing]);
      return { registered: sent.length === 1 };
    };
    expect(await pairHolder("PUB", "#pair=tok-1", register)).toBe("Paired with the desk.");
    expect(await pairHolder("PUB", "#pair=tok-1", register)).toBe(
      "Not paired: this device's key paired with the desk before, or every holder slot is taken.",
    );
    expect(await pairHolder("PUB", "", register)).toBeNull();
    expect(sent).toEqual([["PUB", "tok-1"], ["PUB", "tok-1"]]);
  });
});
