import { describe, expect, it } from "vitest";
import { ATTACK, CONFIRM, patch } from "./__fixtures__/lines";
import { parseHello, parseLine, WireError } from "./parse";

describe("parseLine", () => {
  it("accepts the lines Python writes", () => {
    const confirm = parseLine(CONFIRM);
    const attack = parseLine(ATTACK);
    expect(confirm.seq).toBe(3);
    expect(confirm.forensic?.action_hash).toBe(
      "52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b",
    );
    expect(confirm.forensic?.registry?.siblings).toEqual([]);
    expect(attack.source === "attack" && attack.subject.blocked).toBe(true);
    expect(attack.forensic?.cert_claims).toBeNull();
  });

  it("accepts the holder's intent line", () => {
    const line = parseLine(
      '{"v":3,"seq":1,"source":"desk","event":null,"meta":null,"subject":{"step":"intent","quote_id":null,' +
        '"status":"signed","summary":"Pay 200.00 USD to acme-991 (ref A-991) from checking-881",' +
        '"payment_id":null,"reason":null},"forensic":null}',
    );
    expect(line.source === "desk" && [line.subject.step, line.subject.status]).toEqual(["intent", "signed"]);
  });

  const event = JSON.parse(ATTACK).event;
  const forensic = JSON.parse(CONFIRM).forensic;
  it.each([
    ["not JSON", "{", "wire: not JSON"],
    ["an array", "[]", "wire: not a line"],
    ["v2", patch(ATTACK, { v: 2 }), "wire: malformed line"],
    ["seq 0", patch(ATTACK, { seq: 0 }), "wire: malformed line"],
    ["fractional seq", patch(ATTACK, { seq: 1.5 }), "wire: malformed line"],
    ["unknown source", patch(ATTACK, { source: "bank" }), "wire: malformed line"],
    ["extra key", patch(ATTACK, { extra: 1 }), "wire: malformed line"],
    ["blocked as text", patch(ATTACK, {}, { blocked: "true" }), "wire: malformed line"],
    ["unknown origin", patch(ATTACK, {}, { origin: "human" }), "wire: malformed line"],
    ["extra subject key", patch(ATTACK, {}, { x: 1 }), "wire: malformed line"],
    ["bad desk step", patch(CONFIRM, {}, { step: "pay" }), "wire: malformed line"],
    ["v2 event", patch(ATTACK, { event: { ...event, v: 2 } }), "wire: malformed line"],
    ["meta not object", patch(ATTACK, { meta: "x" }), "wire: malformed line"],
    [
      "registry extra key",
      patch(CONFIRM, { forensic: { ...forensic, registry: { ...forensic.registry, x: 1 } } }),
      "wire: malformed line",
    ],
    [
      "forensic missing key",
      patch(CONFIRM, { forensic: { ...forensic, anchor: undefined } }),
      "wire: malformed line",
    ],
  ])("rejects %s", (_name, text, message) => {
    expect(() => parseLine(text)).toThrow(WireError);
    expect(() => parseLine(text)).toThrow(message);
  });
});

describe("parseHello", () => {
  it("reads epoch and last seq", () => {
    expect(parseHello('{"epoch":"a1b2","last_seq":4}')).toEqual({ epoch: "a1b2", last_seq: 4 });
  });

  it.each(['{"epoch":"a"}', '{"epoch":1,"last_seq":0}', '{"epoch":"a","last_seq":-1}'])(
    "rejects %s",
    (text) => {
      expect(() => parseHello(text)).toThrow("wire: malformed hello");
    },
  );
});
