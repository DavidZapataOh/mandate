import { describe, expect, it } from "vitest";
import { BREACH, DEPLOY_BREACH, FORGED, HQ, lines, PIPE_KIND, WINDOW } from "./__fixtures__/window";
import { computePosture, formatCents, formatShare, layerOf, nearestRank } from "./posture";

const none = { count: 0, seqs: [] };
const quiet = (kind: string) => ({ kind, attempts: 0, blocked: 0, breaches: 0, movedCents: 0, stoppedAt: [], seqs: [] });

describe("computePosture", () => {
  it("counts a real window the way the console counts it", () => {
    expect(computePosture(lines(WINDOW))).toEqual({
      window: { first: 1, last: 9, lines: 9 },
      decided: { count: 7, seqs: [3, 4, 5, 6, 7, 8, 9] },
      verified: { count: 3, seqs: [3, 7, 9] },
      denied: { count: 4, seqs: [4, 5, 6, 8] },
      breaches: none,
      movedCents: 0,
      attacks: [
        { kind: "payee_swap", attempts: 1, blocked: 1, breaches: 0, movedCents: 0, stoppedAt: ["gate"], seqs: [4] },
        quiet("amount_inflate"),
        { kind: "replay", attempts: 1, blocked: 1, breaches: 0, movedCents: 0, stoppedAt: ["bank verifier"], seqs: [6] },
        quiet("post_cert_mutation"),
        quiet("scope_escalation"),
        { kind: "mcp_exfil", attempts: 1, blocked: 1, breaches: 0, movedCents: 0, stoppedAt: ["MCP proxy"], seqs: [5] },
        quiet("forged_approval"),
      ],
      layers: [
        { layer: "gate", denials: 2, kinds: ["payee_swap"], seqs: [4, 8] },
        { layer: "bank verifier", denials: 1, kinds: ["replay"], seqs: [6] },
        { layer: "broker", denials: 0, kinds: [], seqs: [] },
        { layer: "MCP proxy", denials: 1, kinds: ["mcp_exfil"], seqs: [5] },
        { layer: "holder approval", denials: 0, kinds: [], seqs: [] },
        { layer: "desk", denials: 0, kinds: [], seqs: [] },
      ],
      consent: { certified: { count: 2, seqs: [3, 9] }, withConsent: { count: 1, seqs: [3] } },
      latency: { samples: 5, p50Us: 61, p95Us: 90, seqs: [3, 4, 7, 8, 9] },
      attribution: {
        attributed: { count: 4, seqs: [5, 7, 8, 9] },
        byProvider: [
          { provider: "baseten", count: 1 },
          { provider: "meta-model-api", count: 1 },
          { provider: "muse-code", count: 2 },
        ],
      },
    });
  });

  it("an empty window has no window bounds, no samples and no shares", () => {
    const p = computePosture([]);
    expect([p.window, p.decided, p.latency, p.consent.certified, p.movedCents]).toEqual([
      { first: null, last: null, lines: 0 },
      none,
      { samples: 0, p50Us: null, p95Us: null, seqs: [] },
      none,
      0,
    ]);
    expect(p.attacks.map((row) => row.attempts)).toEqual([0, 0, 0, 0, 0, 0, 0]);
  });

  it("an attack that moved money is a breach, never verified, and its cents are counted", () => {
    const p = computePosture(lines([...WINDOW, BREACH]));
    expect([p.decided.count, p.verified.count, p.denied.count, p.breaches, p.movedCents]).toEqual([
      8, 3, 4, { count: 1, seqs: [10] }, 2000000,
    ]);
    expect(p.attacks[1]).toEqual({
      kind: "amount_inflate", attempts: 1, blocked: 0, breaches: 1, movedCents: 2000000, stoppedAt: [], seqs: [10],
    });
  });

  it("Nimbus steps count in the same taxonomy, never as attacks", () => {
    const p = computePosture(lines(HQ));
    expect([p.decided, p.verified, p.denied, p.breaches]).toEqual([
      { count: 3, seqs: [12, 13, 14] },
      { count: 1, seqs: [12] },
      { count: 2, seqs: [13, 14] },
      none,
    ]);
    expect(p.layers.filter((row) => row.denials > 0)).toEqual([
      { layer: "gate", denials: 1, kinds: [], seqs: [14] },
      { layer: "MCP proxy", denials: 1, kinds: [], seqs: [13] },
    ]);
    expect(p.attacks.map((row) => row.attempts)).toEqual([0, 0, 0, 0, 0, 0, 0]);
    expect([p.consent.certified, p.latency.samples, p.attribution.attributed]).toEqual([none, 3, none]);
  });

  it("a Nimbus step that ran when it should have been refused is a breach", () => {
    const p = computePosture(lines([DEPLOY_BREACH]));
    expect([p.breaches, p.verified, p.movedCents]).toEqual([{ count: 1, seqs: [17] }, none, 0]);
  });

  it("a kind outside the seven still gets its own row after them", () => {
    const p = computePosture(lines([PIPE_KIND]));
    expect(p.attacks.map((row) => row.kind)).toEqual([
      "payee_swap", "amount_inflate", "replay", "post_cert_mutation", "scope_escalation", "mcp_exfil", "forged_approval", "x|y",
    ]);
    expect(p.attacks[7]?.stoppedAt).toEqual(["MCP proxy"]);
  });

  it("a forged approval is its own attack row, denied at the gate", () => {
    const p = computePosture(lines([FORGED]));
    expect(p.attacks[6]).toEqual({
      kind: "forged_approval", attempts: 1, blocked: 1, breaches: 0, movedCents: 0, stoppedAt: ["gate"], seqs: [18],
    });
    expect(p.layers[0]).toEqual({ layer: "gate", denials: 1, kinds: ["forged_approval"], seqs: [18] });
  });
});

describe("layerOf", () => {
  it.each([
    [2, "holder approval"],
    [3, "gate"],
    [4, "gate"],
    [5, "MCP proxy"],
    [6, "bank verifier"],
    [8, "gate"],
    [9, "gate"],
  ])("line %i was decided at the %s", (seq, layer) => {
    const line = lines(WINDOW).find((l) => l.seq === seq);
    expect(line && layerOf(line)).toBe(layer);
  });
});

describe("layerOf for Nimbus steps", () => {
  it.each([
    [13, "MCP proxy"],
    [14, "gate"],
  ])("line %i was decided at the %s", (seq, layer) => {
    const line = lines(HQ).find((l) => l.seq === seq);
    expect(line && layerOf(line)).toBe(layer);
  });
});

describe("nearestRank", () => {
  it.each([
    [[12, 30, 61, 61, 90], 50, 61],
    [[12, 30, 61, 61, 90], 95, 90],
    [[1, 2, 3, 4], 50, 2],
    [[1, 2, 3, 4], 95, 4],
    [[5], 95, 5],
  ])("of %j at p%i is %i", (sorted, q, want) => {
    expect(nearestRank(sorted, q)).toBe(want);
  });

  it("of nothing is null", () => {
    expect(nearestRank([], 50)).toBeNull();
  });
});

describe("formatting", () => {
  it.each([
    [1, 2, "1 of 2 · 50.0%"],
    [4, 7, "4 of 7 · 57.1%"],
    [999, 1000, "999 of 1000 · 99.9%"],
    [3, 3, "3 of 3 · 100.0%"],
    [0, 0, "none in this window"],
  ])("share %i of %i reads %s", (part, whole, want) => {
    expect(formatShare(part, whole)).toBe(want);
  });

  it.each([
    [0, "0.00"],
    [5, "0.05"],
    [2000000, "20000.00"],
    [-150, "-1.50"],
  ])("%i cents reads %s", (cents, want) => {
    expect(formatCents(cents)).toBe(want);
  });
});
