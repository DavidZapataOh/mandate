import { describe, expect, it } from "vitest";
import { fromBase64, fromBase64Url, toHex } from "./bytes";
import { canonicalJson, hmacSha256Hex, keyBytes, sha256Hex } from "./canon";
import { anchorDigest, consentBytes, leafHash, readClaims, reasoningCommitment, rootOf, sealBytes } from "./chain";
import { CAVA, CONSENT, CONSENT_KEY, GATE_KEY, HOLDER_KEY, RECEIPT } from "./__fixtures__/receipts";

const golden = JSON.parse(RECEIPT);
const gate = fromBase64(GATE_KEY);

describe("canonical bytes match gate/cava.py", () => {
  it("hashes the desk action to the certified hash under its salt", async () => {
    expect(canonicalJson(CAVA)).toBe(
      '{"category":"payments","evidence_refs":["q:000001"],"executable":"bank.pay","freshness":{"nonce":"00000000000000000000000000000002","timestamp":1800001000},"operation":"transfer","reversible":false,"runtime":"mcp","targets":["amount:USD:20000","from:checking-881","ref:A-991","to:acme-991"],"version":"cava/1"}',
    );
    expect(await hmacSha256Hex("01".repeat(32), canonicalJson(CAVA))).toBe(
      "52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b",
    );
  });

  it("refuses a salt that is not 32 bytes", async () => {
    await expect(hmacSha256Hex("01".repeat(31), "x")).rejects.toThrow("canon: salt must be 32 bytes");
  });

  it("escapes non-ASCII and control characters as Python does", async () => {
    const odd = {
      version: "cava/1", runtime: "muse", executable: "bank.pay", operation: "transfer",
      category: "payments", targets: ["to:acmé", "ref:☃😀", 'note:"q"\\\u001f'], reversible: false,
      freshness: { nonce: "n1", timestamp: 0 }, evidence_refs: [],
    };
    expect(canonicalJson(odd)).toBe(
      '{"category":"payments","evidence_refs":[],"executable":"bank.pay","freshness":{"nonce":"n1","timestamp":0},"operation":"transfer","reversible":false,"runtime":"muse","targets":["to:acm\\u00e9","ref:\\u2603\\ud83d\\ude00","note:\\"q\\"\\\\\\u001f"],"version":"cava/1"}',
    );
    expect(await sha256Hex(canonicalJson(odd))).toBe(
      "624515db3f7490b2bd79e94159ab0e68904d3fc2a3bb82565c082d325e3c81d4",
    );
  });

  it("escapes DEL and orders keys by code point as Python does", () => {
    expect(canonicalJson({ "\uffff": 1, "\u{1F600}": 2, "a\u007f": 3 })).toBe('{"a\\u007f":3,"\\uffff":1,"\\ud83d\\ude00":2}');
  });

  it("refuses numbers Python would format differently", () => {
    expect(() => canonicalJson({ amount: 1.5 })).toThrow("canon: unsupported number");
  });
});

describe("certificate", () => {
  it("reads the claims the gate signed", async () => {
    const read = await readClaims(golden.certificate, gate);
    expect(read).toEqual({
      claims: {
        action_hash: "52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b",
        policy_id: "desk",
        policy_version: 1,
        verdict: "MET",
        freshness_nonce: "00000000000000000000000000000002",
        scope: "mcp:bank.pay:transfer",
        reasoning_commitment: "6b1ae26a9ea91c2c54b03e36e874e2add2be9910e3bc8ed184a70fea39cf6b24",
        evidence_refs: ["q:000001"],
        revocation_index: 1,
      },
    });
  });

  it("rejects the certificate under another key", async () => {
    expect(await readClaims(golden.certificate, fromBase64(HOLDER_KEY))).toEqual({ reason: "bad-signature: eddsa mismatch" });
  });

  it("rejects a payload edited after signing", async () => {
    const [h, p, s] = golden.certificate.split(".");
    const payload = new TextDecoder().decode(fromBase64Url(p)).replace('"desk"', '"dusk"');
    const edited = btoa(payload).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    expect(await readClaims(`${h}.${edited}.${s}`, gate)).toEqual({ reason: "bad-signature: eddsa mismatch" });
  });

  it.each(["", "a.b", "a.b.c", "!!.e30.AA"])("calls %j undecodable", async (token) => {
    expect(await readClaims(token, gate)).toEqual({ reason: "malformed: token undecodable" });
  });

  it("accepts a padded signature segment and refuses a half-padded one, as PyJWT does", async () => {
    expect(await readClaims(`${golden.certificate}==`, gate)).toHaveProperty("claims.policy_id", "desk");
    expect(await readClaims(`${golden.certificate}=`, gate)).toEqual({ reason: "malformed: token undecodable" });
  });

  it("refuses a gate key that is not 32 bytes before reading the token", async () => {
    expect(await readClaims(golden.certificate, gate.slice(1))).toEqual({ reason: "malformed: bad public key" });
  });
});

describe("consent bytes match gate/consent.py", () => {
  it("rebuilds the pinned bytes", () => {
    expect(new TextDecoder().decode(consentBytes(CONSENT))).toBe(
      'consent/v1:{"amount_cents":20000,"currency":"USD","expires_at":1800001600,"nonce":"00000000000000000000000000000001","recipient":"acme-991","reference":"A-991","source":"checking-881"}',
    );
  });

  it.each([
    ["recipient", "acme 991"],
    ["recipient", ""],
    ["amount_cents", 0],
    ["expires_at", -1],
  ])("refuses %s = %j", (field, value) => {
    expect(() => consentBytes({ ...CONSENT, [field]: value })).toThrow("consent: malformed");
  });
});

describe("key certificate bytes match gate/consent.py", () => {
  it("rebuilds the pinned bytes for the desk's first quote", () => {
    expect(new TextDecoder().decode(keyBytes(fromBase64(CONSENT_KEY), CONSENT.nonce))).toBe(
      'consent-key/v1:{"consent_key":"k9ufLuD3456UL7WUQRkL8gucQ8/MigUaFSSZzzkrejc=","nonce":"00000000000000000000000000000001"}',
    );
  });

  it("refuses a short key or a spaced nonce", () => {
    expect(() => keyBytes(fromBase64(CONSENT_KEY).slice(1), CONSENT.nonce)).toThrow("consent: malformed");
    expect(() => keyBytes(fromBase64(CONSENT_KEY), "c0 c0")).toThrow("consent: malformed");
  });
});

describe("registry matches gate/registry.py", () => {
  it("hashes the entry to the proven leaf", async () => {
    expect(await leafHash(golden.registry.entry)).toBe(
      "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87",
    );
  });

  it("recomputes a five-leaf root from the third leaf", async () => {
    expect(
      await rootOf({
        seq: 3,
        leaves: 5,
        leaf: "7ff5bdfbc1cee44cc308158fdcac397a93829d6bfab7d77f1b457fdb4c6a06c8",
        siblings: [
          "d95c00c88961eb7763227de52d47e3cda71c480a24209530524d73e1d35773f1",
          "742c2ba7dcd88ce8a7db2c6ccf01048ba0806810975afce4417a745f5072e71c",
          "ab120101f4ba812de0d3d6f7cae1cc81e8c4326ed52f7f7dfc96b25ed54462a0",
        ],
        root: "30b8e13965a13f0ed519379566777425d2d1b16cf4991eb53b7885e7b3b3c4e2",
      }),
    ).toBe("30b8e13965a13f0ed519379566777425d2d1b16cf4991eb53b7885e7b3b3c4e2");
  });

  it.each([
    { seq: 0, leaves: 1 },
    { seq: 2, leaves: 1 },
    { seq: 1, leaves: 1, leaf: "zz" },
    { seq: 1, leaves: 1, siblings: ["ab"] },
  ])("calls %j malformed", async (change) => {
    expect(await rootOf({ ...golden.registry.proof, ...change })).toBeNull();
  });

  it("signs the seal over the pinned bytes", () => {
    expect(new TextDecoder().decode(sealBytes(golden.registry.seal))).toBe(
      'anchor/v1:["anch:000001","70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87",1,1,1800001000,1]',
    );
  });
});

describe("reasoning anchor matches swarm/anchor.py", () => {
  it("commits to an empty chain", async () => {
    expect(await reasoningCommitment([])).toBe("6b1ae26a9ea91c2c54b03e36e874e2add2be9910e3bc8ed184a70fea39cf6b24");
  });

  it("digests a Meta response anchor", async () => {
    expect(
      await anchorDigest({
        v: 1,
        model: "muse-spark-1.3",
        response_id: "resp_golden_1",
        blobs: ["gAAAAABlb2xkZW4tMQ==", "gAAAAABlb2xkZW4tMg=="],
      }),
    ).toBe("b04c6f8fbf472389afdaadd30fbd4e0d98572b9072d672222eb45dd874587077");
  });
});

it.each([[["a\nb", "c"]], [[""]], [["\ud800"]]])("refuses reasoning blobs %j as Python does", async (blobs) => {
  await expect(reasoningCommitment(blobs)).rejects.toThrow("reasoning: malformed blob");
});

it("hex helper is lowercase", () => {
  expect(toHex(new Uint8Array([0, 171, 255]))).toBe("00abff");
});
