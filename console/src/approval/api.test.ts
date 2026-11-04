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

  it.each([[{ holders: 0 }], [{ holders: 3 }], [{ holders: 16 }]])(
    "reads the device state %j",
    async (body) => {
      expect(await httpDesk(answering(200, body)).device()).toEqual(body);
    },
  );

  it("reads the device state and ignores the holder page's voice flag", async () => {
    const body = { holders: 1, voice: true };
    expect(await httpDesk(answering(200, body)).device()).toEqual({ holders: 1 });
  });

  it.each([
    [{ paired: true, fingerprint: "630dcd2966c43366" }],
    [{ holders: -1 }],
    [{ holders: 17 }],
    [{ holders: 1.5 }],
    [{ holders: "2" }],
    [{ holders: 0, voice: "yes" }],
    [{ holders: 1, key: "x" }],
  ])("refuses the device state %j", async (body) => {
    await expect(httpDesk(answering(200, body)).device()).rejects.toThrow(
      "approval: malformed device state",
    );
  });
});
