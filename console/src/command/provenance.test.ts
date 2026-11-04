import { describe, expect, it } from "vitest";
import { SERVER_BODY, SERVER_BODY_BANK } from "./__fixtures__/provenance";
import { lines, WINDOW } from "./__fixtures__/window";
import { parseProvenance, provenanceOf } from "./provenance";

const ROOT = "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87";
const body = JSON.parse(SERVER_BODY);
const bank = JSON.parse(SERVER_BODY_BANK).bank;

describe("parseProvenance", () => {
  it("reads what the server serves", () => {
    const p = parseProvenance(SERVER_BODY);
    expect([p.epoch, p.registry, p.policies.map((x) => x.policy_id), p.bank]).toEqual([
      "MANDATE_FIXTURE-a1b2c3d4", { root: ROOT, leaves: 1 }, ["desk", "payments", "nimbus"], null,
    ]);
  });

  it("reads the reconciliation the server ran", () => {
    expect(parseProvenance(SERVER_BODY_BANK).bank?.transfers).toBe(3);
    expect(provenanceOf(lines(WINDOW), parseProvenance(SERVER_BODY_BANK), null).bank?.certified).toBe(3);
  });

  it.each([
    ["not JSON", "{"],
    ["an extra key", JSON.stringify({ ...body, extra: 1 })],
    ["leaves as text", JSON.stringify({ ...body, registry: { root: ROOT, leaves: "1" } })],
    ["a short root", JSON.stringify({ ...body, registry: { root: "7056", leaves: 1 } })],
    ["a negative seq", JSON.stringify({ ...body, window: { first_seq: -1, last_seq: 9, retained: 9 } })],
    ["a bank block with an extra key", JSON.stringify({ ...body, bank: { ...bank, url: "x" } })],
    ["unbacked as text", JSON.stringify({ ...body, bank: { ...bank, unbacked: "t1" } })],
    ["a rail it does not know", JSON.stringify({ ...body, bank: { ...bank, rail: "real" } })],
    ["a bank block missing its error", JSON.stringify({ ...body, bank: { ...bank, error: undefined } })],
    ["a fractional count", JSON.stringify({ ...body, bank: { ...bank, transfers: 1.5 } })],
    ["a list holding a number", JSON.stringify({ ...body, bank: { ...bank, missing: [1] } })],
    ["a provider that is not text", JSON.stringify({ ...body, bank: { ...bank, provider: 3 } })],
    ["a rule missing consent_required", JSON.stringify({
      ...body, policies: [{ ...body.policies[0], rules: [{ ...body.policies[0].rules[0], consent_required: undefined }] }],
    })],
  ])("rejects %s", (_name, text) => {
    expect(() => parseProvenance(text)).toThrow("wire: malformed provenance");
  });
});

describe("provenanceOf", () => {
  const window = lines(WINDOW);

  it("a live window rests on the server's registry root and policies", () => {
    expect(provenanceOf(window, parseProvenance(SERVER_BODY), null)).toEqual({
      source: "live", replay: null, epoch: "MANDATE_FIXTURE-a1b2c3d4",
      window: { first: 1, last: 9, lines: 9 }, evicted: false,
      registry: { root: ROOT, leaves: 1, from: "server" },
      policies: body.policies, bank: null,
    });
  });

  it("without the server it takes the newest registry proof a line carries and names that line", () => {
    const p = provenanceOf(window, null, null);
    expect([p.source, p.epoch, p.registry, p.policies]).toEqual([
      "live", null, { root: ROOT, leaves: 1, from: "line #3" }, null,
    ]);
  });

  it("a newer registry proof on the newest line beats an older server value", () => {
    const stale = parseProvenance(JSON.stringify({ ...body, registry: { root: "ab".repeat(32), leaves: 0 } }));
    const p = provenanceOf(window, stale, null);
    expect([p.registry, p.epoch, p.policies?.length]).toEqual([{ root: ROOT, leaves: 1, from: "line #3" }, "MANDATE_FIXTURE-a1b2c3d4", 3]);
  });

  it("a server value with as many entries as the newest proof stays the server's", () => {
    expect(provenanceOf(window, parseProvenance(SERVER_BODY), null).registry?.from).toBe("server");
  });

  it("a replay never carries the live reconciliation", () => {
    expect(provenanceOf(window, parseProvenance(SERVER_BODY_BANK), "demo-1").bank).toBeNull();
  });

  it("a replay says so and serves no policies", () => {
    const p = provenanceOf(window, null, "demo-1");
    expect([p.source, p.replay, p.registry?.from, p.policies]).toEqual(["replay", "demo-1", "line #3", null]);
  });

  it("a replay ignores a live server's policies, registry and epoch whatever the caller passes", () => {
    const p = provenanceOf(window, parseProvenance(SERVER_BODY), "demo-1");
    expect([p.source, p.epoch, p.registry?.from, p.policies]).toEqual(["replay", null, "line #3", null]);
  });

  it("a window that starts after #1 is marked as missing its earlier lines", () => {
    const p = provenanceOf(window.slice(3), null, null);
    expect([p.window, p.evicted, p.registry]).toEqual([{ first: 4, last: 9, lines: 6 }, true, null]);
  });

  it("an empty window has no bounds and no registry", () => {
    expect(provenanceOf([], null, null)).toEqual({
      source: "live", replay: null, epoch: null, window: { first: null, last: null, lines: 0 },
      evicted: false, registry: null, policies: null, bank: null,
    });
  });
});
