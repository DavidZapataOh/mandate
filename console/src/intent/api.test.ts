// @vitest-environment node
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ACME, CLIP_PROOF, DRAFT, DRAFT_BODY, DRAFT_PROOF, INTENT_SIGNATURE, seedKeys, SIGNED, START_BODY, START_PROOF } from "./__fixtures__/desk";
import { DeskError, deviceProof, httpIntentApi } from "./api";

const CLIP = new URL("../../../demo/voice/pay-acme.wav", import.meta.url);
const IDLE = { state: "idle", intent_id: null, quote_id: null, detail: "" };

interface Sent {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: Uint8Array | null;
}

async function bodyBytes(body: BodyInit | null | undefined): Promise<Uint8Array | null> {
  if (body === undefined || body === null) return null;
  return new Uint8Array(await new Response(body).arrayBuffer());
}

/** A fetch that answers `status`/`answer` and records what was sent. */
function recording(status: number, answer: unknown): { sent: Sent[]; fetchFn: typeof fetch } {
  const sent: Sent[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    sent.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      body: await bodyBytes(init?.body),
    });
    const text = typeof answer === "string" ? answer : JSON.stringify(answer);
    return new Response(text, { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { sent, fetchFn };
}

const text = (bytes: Uint8Array | null) => (bytes === null ? null : new TextDecoder().decode(bytes));

describe("device proof", () => {
  it("signs the domain and the body's sha256 as the desk checks it", async () => {
    const { privateKey } = await seedKeys();
    const body = new TextEncoder().encode(DRAFT_BODY);
    expect(await deviceProof(privateKey, "mandate/intent-draft/v1", body)).toBe(DRAFT_PROOF);
    expect(await deviceProof(privateKey, "mandate/agent-start/v1", new TextEncoder().encode(START_BODY))).toBe(START_PROOF);
  });
});

describe("httpIntentApi", () => {
  it("drafts from text with the exact body it signs", async () => {
    const { sent, fetchFn } = recording(200, DRAFT);
    const api = httpIntentApi("https://desk.test", (await seedKeys()).privateKey, fetchFn);
    expect(await api.draftText("Pay my Acme Corp bill A-991, 200 USD")).toEqual(DRAFT);
    expect(sent.map((s) => [s.url, s.method, s.headers["content-type"], s.headers["x-mandate-device-sig"], text(s.body)])).toEqual([
      ["https://desk.test/api/intent/draft", "POST", "application/json", DRAFT_PROOF, DRAFT_BODY],
    ]);
  });

  it("uploads the raw clip as audio/wav with its device proof", async () => {
    const bytes = readFileSync(CLIP);
    const clip = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const { sent, fetchFn } = recording(200, DRAFT);
    const api = httpIntentApi("", (await seedKeys()).privateKey, fetchFn);
    await api.draftVoice(clip);
    const [only] = sent;
    expect([only?.url, only?.method, only?.headers["content-type"], only?.headers["x-mandate-device-sig"]]).toEqual([
      "/api/intent/voice", "POST", "audio/wav", CLIP_PROOF,
    ]);
    expect(Buffer.from(only?.body ?? []).equals(bytes)).toBe(true);
  });

  it("posts the signed intent without a device header", async () => {
    const { sent, fetchFn } = recording(200, SIGNED);
    const api = httpIntentApi("", (await seedKeys()).privateKey, fetchFn);
    expect(await api.sign(ACME, INTENT_SIGNATURE)).toEqual(SIGNED);
    const [only] = sent;
    expect([only?.url, only?.headers["content-type"], only?.headers["x-mandate-device-sig"]]).toEqual([
      "/api/intent", "application/json", undefined,
    ]);
    expect(JSON.parse(text(only?.body ?? null) ?? "")).toEqual({ intent: ACME, signature: INTENT_SIGNATURE });
  });

  it("hands over only the intent id, signed, and reads the run unsigned", async () => {
    const { sent, fetchFn } = recording(202, IDLE);
    const api = httpIntentApi("", (await seedKeys()).privateKey, fetchFn);
    await api.handoff("i:000001");
    await api.agent();
    expect(sent.map((s) => [s.url, s.method, s.headers["x-mandate-device-sig"], text(s.body)])).toEqual([
      ["/api/agent/start", "POST", START_PROOF, START_BODY],
      ["/api/agent", "GET", undefined, null],
    ]);
  });

  it.each([
    [401, { error: "not the paired device" }, "not the paired device"],
    [503, { error: "model unavailable" }, "model unavailable"],
    [502, "<html>bad gateway</html>", "HTTP 502"],
    [400, { detail: "no error key" }, "HTTP 400"],
  ])("turns a %i answer into a DeskError", async (status, answer, message) => {
    const { fetchFn } = recording(status, answer);
    const api = httpIntentApi("", (await seedKeys()).privateKey, fetchFn);
    const failed = await api.draftText("x").catch((error: unknown) => error);
    expect(failed).toBeInstanceOf(DeskError);
    expect([(failed as DeskError).status, (failed as DeskError).message]).toEqual([status, message]);
  });
});
