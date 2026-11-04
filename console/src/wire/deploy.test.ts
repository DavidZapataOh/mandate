import { describe, expect, it } from "vitest";
import { DEPLOY, patch } from "./__fixtures__/lines";
import { parseLine, WireError } from "./parse";

describe("deploy lines on the wire", () => {
  it("accepts the line Python writes", () => {
    const line = parseLine(DEPLOY);
    expect(line.source === "deploy" && [line.subject.step, line.subject.layer, line.subject.blocked]).toEqual([
      "release",
      "gate",
      false,
    ]);
    expect(line.forensic?.cert_claims?.["scope"]).toBe("nimbus:prod-eu");
  });

  it.each([
    ["an unknown step", patch(DEPLOY, {}, { step: "rollback" })],
    ["blocked as text", patch(DEPLOY, {}, { blocked: "false" })],
    ["an extra subject key", patch(DEPLOY, {}, { origin: "template" })],
    ["a missing subject key", patch(DEPLOY, {}, { agent: undefined })],
  ])("rejects %s", (_name, text) => {
    expect(() => parseLine(text)).toThrow(WireError);
    expect(() => parseLine(text)).toThrow("wire: malformed line");
  });
});
