import { describe, expect, it } from "vitest";
import { parseLine } from "../wire/parse";
import { CARD, patch, RETURNED, SANDBOX_CONFIRM, SETTLED } from "../wire/__fixtures__/lines";
import { attackLine, BANK_OTHER, BANK_REPORT, BREACH, DEPLOY_BREACH, FORGED, HQ, lines, PIPE_KIND, SANDBOX_PAY, SANDBOX_REFUSED, WINDOW } from "./__fixtures__/window";
import { bankEventsText, computePosture, counted, DEFINITIONS, formatCents, formatShare, LAYERS, layerOf, nearestRank, railsText } from "./posture";

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
      stepsRan: none,
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
        { layer: "holder intent", denials: 0, kinds: [], seqs: [] },
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
      rails: [{ rail: "simulated", count: 2, seqs: [3, 9] }],
      bankEvents: { events: none, reported: none },
      returned: [],
    });
  });

  it("groups verified payments by the rail that moved them", () => {
    const p = computePosture(lines([...WINDOW, SANDBOX_PAY, SANDBOX_REFUSED]));
    expect(p.rails).toEqual([
      { rail: "sandbox", count: 1, seqs: [18] },
      { rail: "simulated", count: 2, seqs: [3, 9] },
    ]);
    expect(computePosture([]).rails).toEqual([]);
  });

  it("bank events are counted on their own and match the payments they name", () => {
    const base = computePosture(lines([...WINDOW, SANDBOX_PAY]));
    const p = computePosture(lines([...WINDOW, SANDBOX_PAY, BANK_REPORT, BANK_OTHER]));
    expect(p.bankEvents).toEqual({ events: { count: 2, seqs: [20, 21] }, reported: { count: 1, seqs: [18] } });
    expect([p.decided, p.verified, p.denied, p.rails]).toEqual([base.decided, base.verified, base.denied, base.rails]);
    expect(bankEventsText(p)).toBe("2 events · 1 of 1 sandbox payment reported by the bank");
    expect(bankEventsText(computePosture(lines([BANK_OTHER])))).toBe("1 event");
    expect(bankEventsText(computePosture(lines([...WINDOW, SANDBOX_PAY, BANK_OTHER])))).toBe(
      "1 event · 0 of 1 sandbox payment reported by the bank",
    );
    expect(bankEventsText(computePosture([]))).toBe("no bank events in this window");
  });

  it("a bank event that comes before the payment it names still matches it", () => {
    const p = computePosture(lines([patch(BANK_REPORT, { seq: 17 }), SANDBOX_PAY]));
    expect(p.bankEvents.reported).toEqual({ count: 1, seqs: [18] });
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

  it("Nimbus steps and holder intents count in the same taxonomy, never as attacks", () => {
    const p = computePosture(lines(HQ));
    expect([p.decided, p.verified, p.denied, p.breaches]).toEqual([
      { count: 4, seqs: [12, 13, 14, 15] },
      { count: 1, seqs: [12] },
      { count: 3, seqs: [13, 14, 15] },
      none,
    ]);
    expect(p.layers.filter((row) => row.denials > 0)).toEqual([
      { layer: "gate", denials: 1, kinds: [], seqs: [14] },
      { layer: "MCP proxy", denials: 1, kinds: [], seqs: [13] },
      { layer: "holder intent", denials: 1, kinds: [], seqs: [15] },
    ]);
    expect(p.attacks.map((row) => row.attempts)).toEqual([0, 0, 0, 0, 0, 0, 0]);
    expect([p.consent.certified, p.latency.samples, p.attribution.attributed]).toEqual([none, 3, none]);
  });

  it("a Nimbus step that ran when it should have been refused is a breach", () => {
    const p = computePosture(lines([DEPLOY_BREACH]));
    expect([p.breaches, p.stepsRan, p.verified, p.movedCents]).toEqual([none, { count: 1, seqs: [17] }, none, 0]);
    expect(p.decided).toEqual({ count: 1, seqs: [17] });
  });

  it("a window of blocked attacks plus one Nimbus step that ran counts the two apart", () => {
    const p = computePosture(lines([...WINDOW, DEPLOY_BREACH]));
    expect([p.breaches, p.stepsRan]).toEqual([none, { count: 1, seqs: [17] }]);
    expect(p.attacks.reduce((n, a) => n + a.breaches, 0)).toBe(0);
  });

  it("moved cents add up by size per breach, so opposite moves never net to zero", () => {
    const p = computePosture(lines([
      attackLine(20, "payee_swap", "model->gate", "ok: executed", null, false, 500),
      attackLine(21, "payee_swap", "model->gate", "ok: executed", null, false, -500),
    ]));
    expect([p.movedCents, p.breaches.count, p.attacks[0]!.movedCents]).toEqual([1000, 2, 1000]);
  });

  it("a negative move on an attack that says it was blocked is still a breach", () => {
    const p = computePosture(lines([attackLine(22, "payee_swap", "gate", "payee: differs", null, true, -300)]));
    expect([p.breaches.count, p.movedCents]).toEqual([1, 300]);
  });

  it("states what the latency covers for hook lines and how bill payments count for consent", () => {
    expect(DEFINITIONS.latency).toMatch(/hook/);
    expect(DEFINITIONS.latency).toMatch(/state lock/);
    expect(DEFINITIONS.consent).toMatch(/Bill payments run under the holder's signed intent/);
    expect(DEFINITIONS.consent).toMatch(/count as without consent/);
    expect(DEFINITIONS.breaches).toMatch(/^Attack lines/);
    expect(DEFINITIONS.stepsRan).toMatch(/Nimbus/);
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

describe("layerOf for Nimbus steps and intents", () => {
  it.each([
    [13, "MCP proxy"],
    [14, "gate"],
    [15, "holder intent"],
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

describe("counted", () => {
  it("is singular for one", () => {
    expect([counted(1, "provision", "provisions"), counted(17, "provision", "provisions"), counted(0, "line", "lines")]).toEqual([
      "1 provision", "17 provisions", "0 lines",
    ]);
  });
});

describe("definitions name holder intents", () => {
  it("says signed intents are not decisions and refused ones are denials at their own layer", () => {
    expect(LAYERS).toEqual(["gate", "bank verifier", "broker", "MCP proxy", "holder approval", "holder intent", "desk"]);
    expect(DEFINITIONS.decided).toMatch(
      /^Lines in this window whose outcome is verified, denied or not blocked\. Signed intents, quotes and approvals waiting for the holder, and bill reads that never reached the gate, are not decisions\.$/,
    );
    expect(DEFINITIONS.denied.endsWith(", Nimbus scenario steps refused at the MCP proxy or gate, and holder intents the desk refused.")).toBe(true);
    expect(DEFINITIONS.layers).toBe(
      "Where each denial happened: the layer that refused the action (gate, bank verifier, broker, MCP proxy, holder approval, holder intent, desk).",
    );
  });
});

describe("returned payments", () => {
  it("posture: a returned payment leaves its rail and is named returned", () => {
    const paid = patch(SANDBOX_CONFIRM, {
      seq: 5,
      subject: { ...JSON.parse(SANDBOX_CONFIRM).subject, payment_id: "ach_transfer_t1" },
    });
    const p = computePosture([parseLine(paid), parseLine(RETURNED)]);
    expect(p.rails).toEqual([]);
    expect(p.returned).toEqual([8]);
    expect(railsText(p)).toBe("no verified payments in this window · 1 returned (SIMULATED RETURN)");
    expect(layerOf(parseLine(SETTLED))).toBe("bank");
    expect(p.decided.count).toBe(1);
  });
});

describe("card answers", () => {
  it("posture: a card answer is a note; the confirm it rides on counts once, as SANDBOX", () => {
    const decision = "sandbox_real_time_decision_b4ni7vda7z380dn9lb5x";
    const paid = patch(SANDBOX_CONFIRM, { seq: 5, subject: { ...JSON.parse(SANDBOX_CONFIRM).subject, payment_id: decision } });
    const p = computePosture([parseLine(paid), parseLine(CARD)]);
    expect([p.decided.count, p.verified.count, railsText(p)]).toEqual([1, 1, "SANDBOX 1"]);
    expect(computePosture([parseLine(CARD)]).decided.count).toBe(0);
    expect(layerOf(parseLine(CARD))).toBe("desk");
  });
});
