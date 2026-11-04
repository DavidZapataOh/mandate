import { describe, expect, it } from "vitest";
import { fromBase64 } from "./bytes";
import { CONSENT_KEY, GATE_KEY, HOLDER_KEY, RECEIPT, disclosureText, gateToken } from "./__fixtures__/receipts";
import { disclosureDigest, processSdJwt, readDisclosure, RECEIPT_TYP } from "./sdjwt";

const gate = fromBase64(GATE_KEY);
const sd: string = JSON.parse(RECEIPT).sd;
const [token, ...rest] = sd.split("~");
const disclosures = rest.slice(0, -1);

describe("processSdJwt matches gate/sdjwt.py", () => {
  it("digests a Disclosure as RFC 9901 does", async () => {
    expect(await disclosureDigest("WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0")).toBe(
      "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0",
    );
    expect(await disclosureDigest(disclosures[1]!)).toBe("m2Kk_cC-TIsWLIGmsn1iPj4XdQRKNYBZhHIXy75fN40");
  });
  it("rebuilds the fully disclosed payload", async () => {
    const out = await processSdJwt(sd, gate, RECEIPT_TYP);
    expect("payload" in out && out.payload.consent).toEqual({
      nonce: "00000000000000000000000000000001", expires_at: 1800001600, consent_key: CONSENT_KEY, source: "checking-881",
      holder_key: HOLDER_KEY, amount_cents: 20000, currency: "USD", recipient: "acme-991", reference: "A-991",
      signature: "OORzeXDe6eaiUsW4PdqrQGhplcplmWCgI+yt3WYVkQR34lDISLG3GHAMrfd0amy/IncXYk95hGubzPgB5jg+AQ==",
      key_signature: "Y9mn3uyjzxkfa7dU2VaNj5Qd59KrV+EuE/HAsQNq3Bs8j7Gf2oQTM4nW+5I73qc/wAKepMESV94VRMvga8YFBg==",
    });
    expect("payload" in out && (out.payload.cava as Record<string, unknown>).action_salt).toBe("01".repeat(32));
    expect("payload" in out && [...out.disclosed].sort()).toEqual([
      "action_salt", "amount_cents", "currency", "holder_key", "key_signature", "recipient", "reference", "signature",
      "source", "targets",
    ]);
  });
  it("hides every concealed claim when nothing is disclosed", async () => {
    const out = await processSdJwt(`${token}~`, gate, RECEIPT_TYP);
    expect("payload" in out && Object.keys(out.payload.consent as object)).toEqual(["nonce", "expires_at", "consent_key"]);
    expect("payload" in out && "action_salt" in (out.payload.cava as object)).toBe(false);
    expect("payload" in out && "_sd_alg" in out.payload).toBe(false);
  });
  it.each([
    ["a missing trailing tilde", token!, "sd-jwt: malformed"],
    ["another issuer", `${token}~`, "sd-jwt: bad signature"],
    ["a repeated disclosure", `${token}~${disclosures[1]}~${disclosures[1]}~`, "sd-jwt: disclosure repeated"],
    ["a disclosure the issuer never signed", `${token}~WyJhIiwiYiIsMV0~`, "sd-jwt: disclosure not referenced"],
  ])("refuses %s", async (_n, text, reason) => {
    const key = reason === "sd-jwt: bad signature" ? fromBase64(HOLDER_KEY) : gate;
    expect(await processSdJwt(text, key, RECEIPT_TYP)).toEqual({ reason });
  });
  it("refuses another token type", async () => {
    expect(await processSdJwt(`${token}~`, gate, "secevent+jwt")).toEqual({ reason: "sd-jwt: wrong type" });
  });
});

const HEADER = '{"alg":"EdDSA","typ":"mandate-receipt+sd-jwt"}';

/** A gate-signed SD-JWT over `claims` whose top-level `_sd` references every Disclosure given. */
async function issued(claims: Record<string, unknown>, ...texts: string[]): Promise<string> {
  const _sd = await Promise.all(texts.map(disclosureDigest));
  const body = texts.length > 0 ? { ...claims, _sd } : claims;
  return [await gateToken(HEADER, JSON.stringify(body)), ...texts, ""].join("~");
}

describe("processSdJwt edge cases follow gate/sdjwt.py process", () => {
  it.each([
    ["non-ASCII input", async () => `${token}~é~`, "sd-jwt: malformed"],
    ["an empty middle disclosure", async () => `${token}~~`, "sd-jwt: disclosure not referenced"],
    ["a top-level disclosure named _sd_alg", async () => issued({ _sd_alg: "sha-256" }, disclosureText("_sd_alg", "x")), "sd-jwt: claim name refused"],
    ["a disclosure named _sd", async () => issued({}, disclosureText("_sd", "x")), "sd-jwt: claim name refused"],
    ["a disclosure with a non-string name", async () => issued({}, disclosureText(5, "x")), "sd-jwt: claim name refused"],
    ["a disclosure naming a visible claim", async () => issued({ iss: "m" }, disclosureText("iss", "x")), "sd-jwt: claim name refused"],
    ["a disclosure of two elements", async () => issued({}, "WyJhIiwiYiJd"), "sd-jwt: disclosure malformed"],
    ["an array element disclosure", async () => issued({ a: [{ "...": "x" }] }), "sd-jwt: array disclosures unsupported"],
    ["a digest met twice", async () => issued({ a: { _sd: ["q"] }, b: { _sd: ["q"] } }), "sd-jwt: digest repeated"],
    ["an _sd that is not a list", async () => issued({ _sd: "q" }), "sd-jwt: malformed"],
    ["another digest algorithm", async () => issued({ _sd_alg: "sha-512" }), "sd-jwt: unsupported digest"],
    ["an audience no verifier asked for", async () => issued({ aud: "x" }), "sd-jwt: malformed"],
    ["a subject that is not a string", async () => issued({ sub: 1 }), "sd-jwt: malformed"],
    ["a payload that is not an object", async () => `${await gateToken(HEADER, "[]")}~`, "sd-jwt: malformed"],
    ["a non-string key id", async () => `${await gateToken('{"alg":"EdDSA","typ":"mandate-receipt+sd-jwt","kid":1}', "{}")}~`, "sd-jwt: malformed"],
  ])("refuses %s", async (_n, make, reason) => {
    expect(await processSdJwt(await make(), gate, RECEIPT_TYP)).toEqual({ reason });
  });

  it("refuses a gate key that is not 32 bytes as malformed", async () => {
    expect(await processSdJwt(`${token}~`, gate.slice(1), RECEIPT_TYP)).toEqual({ reason: "sd-jwt: malformed" });
  });

  it("accepts a padded signature segment, a non-string salt and a nested disclosure", async () => {
    expect(await processSdJwt(`${token}==~`, gate, RECEIPT_TYP)).toHaveProperty("payload.sub", "pay:000001");
    expect(await processSdJwt(await issued({}, disclosureText("x", 1, 7)), gate, RECEIPT_TYP)).toEqual({
      payload: { x: 1 }, disclosed: ["x"],
    });
    const inner = disclosureText("y", 2);
    const outer = disclosureText("x", { _sd: [await disclosureDigest(inner)] });
    const text = [await gateToken(HEADER, JSON.stringify({ _sd: [await disclosureDigest(outer)] })), inner, outer, ""].join("~");
    expect(await processSdJwt(text, gate, RECEIPT_TYP)).toEqual({ payload: { x: { y: 2 } }, disclosed: ["x", "y"] });
  });

  it("keeps a disclosed __proto__ as plain data", async () => {
    const out = await processSdJwt(await issued({}, disclosureText("__proto__", { z: 1 })), gate, RECEIPT_TYP);
    expect("payload" in out && Object.getPrototypeOf(out.payload)).toBe(Object.prototype);
    expect("payload" in out && Object.getOwnPropertyDescriptor(out.payload, "__proto__")?.value).toEqual({ z: 1 });
  });

  it("reads a Disclosure only as a three-element array with string salt and name", () => {
    expect(readDisclosure(disclosures[0]!)).toEqual({
      name: "targets", value: ["amount:USD:20000", "from:checking-881", "ref:A-991", "to:acme-991"],
    });
    expect(readDisclosure(disclosureText("x", 1, 7))).toBeNull();
    expect(readDisclosure("WyJhIiwiYiJd")).toBeNull();
    expect(readDisclosure("!!")).toBeNull();
  });
});
