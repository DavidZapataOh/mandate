import { describe, expect, it } from "vitest";
import { httpDesk } from "./api";
import { FIELDS } from "./__fixtures__/desk";

function answering(status: number, body: unknown, seen: string[] = []): typeof fetch {
  return async (input) => {
    seen.push(String(input));
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
}

describe("httpDesk", () => {
  it("keeps only each pending quote's id and consent fields", async () => {
    const seen: string[] = [];
    const quote = {
      status: "quoted",
      quote_id: "q:000001",
      summary: "Pay 1.00 USD to friend-001",
      consent: FIELDS,
    };
    const quotes = await httpDesk(answering(200, { pending: [quote] }, seen)).pending();
    expect(quotes).toEqual([{ quote_id: "q:000001", consent: FIELDS }]);
    expect(seen).toEqual(["/api/pending"]);
  });

  it.each([
    ["no list", {}],
    ["a quote without an id", { pending: [{ consent: FIELDS }] }],
    [
      "a quote with a malformed consent",
      { pending: [{ quote_id: "q:000001", consent: { ...FIELDS, amount_cents: -5 } }] },
    ],
  ])("refuses a pending answer with %s", async (_name, body) => {
    await expect(httpDesk(answering(200, body)).pending()).rejects.toThrow(
      /^approval: malformed/,
    );
  });

  it("names the status when the desk refuses", async () => {
    const desk = httpDesk(answering(400, { error: "bad request" }));
    await expect(desk.pending()).rejects.toThrow("approval: desk answered 400");
  });

  it.each([
    [{ paired: false, fingerprint: null }],
    [{ paired: true, fingerprint: "630dcd2966c43366" }],
  ])("reads the device state %j", async (body) => {
    expect(await httpDesk(answering(200, body)).device()).toEqual(body);
  });

  it("reads the device state and ignores the holder page's voice flag", async () => {
    const body = { paired: true, fingerprint: "630dcd2966c43366", voice: true };
    expect(await httpDesk(answering(200, body)).device()).toEqual({
      paired: true,
      fingerprint: "630dcd2966c43366",
    });
  });

  it.each([
    [{ paired: true, fingerprint: null }],
    [{ paired: false, fingerprint: null, voice: "yes" }],
    [{ paired: false, fingerprint: "630dcd2966c43366" }],
    [{ paired: true, fingerprint: "630DCD2966C43366" }],
    [{ paired: "yes", fingerprint: null }],
    [{ paired: false, fingerprint: null, key: "x" }],
  ])("refuses the device state %j", async (body) => {
    await expect(httpDesk(answering(200, body)).device()).rejects.toThrow(
      "approval: malformed device state",
    );
  });
});
