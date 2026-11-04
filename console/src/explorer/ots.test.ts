import { describe, expect, it } from "vitest";
import OTS from "./__fixtures__/ots.json" with { type: "json" };
import { concat, fromBase64, fromHex } from "./bytes";
import { MAX_PROOF_BYTES, OtsError, readHeader, readOts } from "./ots";

const CALENDARS = [
  "https://alice.btc.calendar.opentimestamps.org",
  "https://bob.btc.calendar.opentimestamps.org",
  "https://btc.calendar.catallaxy.com",
  "https://finney.calendar.eternitywall.com",
];
const MAGIC = "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294";
const ZERO = "00".repeat(32);
const upgraded = fromBase64(OTS.core29.upgraded);
const uris = (p: { attestations: { kind: string }[] }) =>
  p.attestations.flatMap((a) => ("uri" in a ? [a.uri as string] : [])).sort();

describe("readOts", () => {
  it("reads every attestation of a proof the reference client upgraded", async () => {
    const proof = await readOts(upgraded);
    expect(proof.digest).toBe("94ec151f452a221393d08f6b02fb30baacbeb59f194611f49069e7f5509b46fe");
    const bitcoin = proof.attestations.flatMap((a) => (a.kind === "bitcoin" ? [a] : []));
    expect(bitcoin.map((a) => a.height).sort((x, y) => x - y)).toEqual([892418, 892421, 892459, 892534]);
    expect(bitcoin.find((a) => a.height === 892418)?.msg).toBe("da26027536e777ac57f0089d885b0cc9e0ab69fe37318979a1deaaf1a392ccb0");
    expect(uris(proof)).toEqual(CALENDARS);
  });

  it("reads a fresh stamp of the golden seal's anchor digest as calendars only", async () => {
    const proof = await readOts(fromBase64(OTS.golden.pending));
    expect(proof.digest).toBe(OTS.golden.digest);
    expect(proof.attestations.every((a) => a.kind === "pending")).toBe(true);
    expect(uris(proof)).toEqual(CALENDARS);
  });

  it("refuses operations current calendars never use", async () => {
    await expect(readOts(fromBase64(OTS.hello2015.proof))).rejects.toThrow(new OtsError("unsupported operation 0x03"));
  });

  it.each([
    ["6e6f7065", "not an OpenTimestamps proof"],
    [`${MAGIC}02`, "unsupported version 2"],
    [`${MAGIC}0102`, "not a SHA-256 proof"],
    [`${MAGIC}0108${"00".repeat(31)}`, "truncated"],
    [`${MAGIC}0108${ZERO}f000`, "bad length"],
    [`${MAGIC}0108${ZERO}f0${"ff".repeat(9)}01`, "varuint too long"],
    [`${MAGIC}0108${ZERO}${"08".repeat(257)}000588960d73d719010101`, "too deep"],
    [`${MAGIC}0108${ZERO}0083dfe30d2ef90c8e0201ff`, "attestation malformed"],
  ])("refuses malformed proofs %#", async (hex, reason) => {
    await expect(readOts(fromHex(hex))).rejects.toThrow(new OtsError(reason));
  });

  it("refuses a proof cut short, one with bytes left over, and one too large", async () => {
    await expect(readOts(upgraded.slice(0, -1))).rejects.toThrow(new OtsError("truncated"));
    await expect(readOts(concat(upgraded, fromHex("00")))).rejects.toThrow(new OtsError("trailing bytes"));
    await expect(readOts(new Uint8Array(MAX_PROOF_BYTES + 1))).rejects.toThrow(new OtsError("proof too large"));
  });
});

describe("readHeader", () => {
  it("reads a header's hash, merkle root, time and work", async () => {
    expect(await readHeader(fromHex(OTS.core29.headers["892418"]))).toEqual({
      hash: "0000000000000000000167a45f26c2afb6a0df3009f8241a647b950a79e3da58",
      merkleRoot: "da26027536e777ac57f0089d885b0cc9e0ab69fe37318979a1deaaf1a392ccb0",
      time: 1744655054,
      meetsTarget: true,
      aboveFloor: true,
    });
  });

  it("flags a header whose hash misses its target", async () => {
    const header = fromHex(OTS.core29.headers["892418"]);
    header[79] = (header[79] ?? 0) ^ 1;
    expect((await readHeader(header)).meetsTarget).toBe(false);
  });

  it("flags a 2015 header as below the work floor", async () => {
    const read = await readHeader(fromHex(OTS.hello2015.header));
    expect([read.hash, read.meetsTarget, read.aboveFloor]).toEqual([
      "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319", true, false,
    ]);
  });
});

const btc = (varuint: string) => `000588960d73d71901${(varuint.length / 2).toString(16).padStart(2, "0")}${varuint}`;
const PENDING_TAG = "0083dfe30d2ef90c8e";
const proofOf = (tree: string) => fromHex(`${MAGIC}0108${ZERO}${tree}`);

describe("readOts, parity with python-opentimestamps", () => {
  it("accepts 255 nested operations and refuses 256", async () => {
    const proof = await readOts(proofOf(`${"08".repeat(255)}${btc("01")}`));
    expect(proof.attestations).toEqual([
      { kind: "bitcoin", height: 1, msg: "49b85ae5536901b2da5e912fd05a88922223194146c668a7cdaaddc79563018e" },
    ]);
    await expect(readOts(proofOf(`${"08".repeat(256)}${btc("01")}`))).rejects.toThrow(new OtsError("too deep"));
  });

  it.each([
    ["ff08" + btc("01") + "08" + btc("02")],
    ["fff001aa" + btc("01") + "f001aa" + btc("02")],
  ])("refuses an operation repeated among one node's branches %#", async (tree) => {
    await expect(readOts(proofOf(tree))).rejects.toThrow(new OtsError("repeated operation"));
  });

  it("reads every branch of a node with distinct operations", async () => {
    const proof = await readOts(proofOf(`fff001aa${btc("01")}08${btc("02")}`));
    expect(proof.attestations).toEqual([
      { kind: "bitcoin", height: 1, msg: `${ZERO}aa` },
      { kind: "bitcoin", height: 2, msg: "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925" },
    ]);
  });

  it("accepts a height of 0xffffffff and refuses anything above it", async () => {
    expect((await readOts(proofOf(btc("ffffffff0f")))).attestations).toEqual([
      { kind: "bitcoin", height: 0xffffffff, msg: ZERO },
    ]);
    await expect(readOts(proofOf(btc("8080808010")))).rejects.toThrow(new OtsError("attestation malformed"));
    await expect(readOts(proofOf(btc("818080808080808010")))).rejects.toThrow(
      new OtsError("attestation malformed"),
    );
  });

  it("accepts an append whose result is 4096 bytes", async () => {
    const proof = await readOts(proofOf(`f0e01f${"aa".repeat(4064)}${btc("01")}`));
    expect(proof.attestations).toEqual([{ kind: "bitcoin", height: 1, msg: `${ZERO}${"aa".repeat(4064)}` }]);
  });

  it("skips an attestation of an unknown kind", async () => {
    const proof = await readOts(proofOf(`ff0011223344556677880100${btc("05")}`));
    expect(proof.attestations).toEqual([{ kind: "bitcoin", height: 5, msg: ZERO }]);
  });

  it.each([
    ["f08120", "bad length"],
    [`f0e11f${"aa".repeat(4065)}${btc("01")}`, "bad length"],
    [`${PENDING_TAG}8140`, "bad length"],
    [`${PENDING_TAG}eb07e907${"61".repeat(1001)}`, "attestation malformed"],
    [`${PENDING_TAG}02013f`, "attestation malformed"],
    [`${PENDING_TAG}03016100`, "attestation malformed"],
  ])("refuses a proof breaking a size or attestation rule %#", async (tree, reason) => {
    await expect(readOts(proofOf(tree))).rejects.toThrow(new OtsError(reason));
  });
});

describe("readHeader, compact targets", () => {
  const withBits = (bits: number) => {
    const header = fromHex(OTS.core29.headers["892418"]);
    new DataView(header.buffer).setUint32(72, bits, true);
    return header;
  };

  it("refuses a header that is not 80 bytes", async () => {
    const header = fromHex(OTS.core29.headers["892418"]);
    await expect(readHeader(concat(header, fromHex("00")))).rejects.toThrow();
    await expect(readHeader(header.slice(0, 79))).rejects.toThrow();
  });

  // Targets written out by Bitcoin Core's SetCompact rule: a zero or negative mantissa is target 0;
  // 0x227fffff is 0x7fffff * 2^248, above every hash and far above the floor.
  it.each([
    [0x22000000, false, true],
    [0x2280ffff, false, true],
    [0x0200ffff, false, true],
    [0x01003fff, false, true],
    [0x227fffff, true, false],
  ])("reads nBits %#", async (bits, meetsTarget, aboveFloor) => {
    const read = await readHeader(withBits(bits));
    expect([read.meetsTarget, read.aboveFloor]).toEqual([meetsTarget, aboveFloor]);
  });

  it("puts a target of exactly 2^180 at the floor and one more above it", async () => {
    expect((await readHeader(withBits(0x17100000))).aboveFloor).toBe(true);
    expect((await readHeader(withBits(0x17100001))).aboveFloor).toBe(false);
  });
});
