// @vitest-environment node
import { expect, test } from "vitest";
import { edit, generate, museKey, provenance, type Fetch } from "./muse_image.ts";

const WEBP = new Uint8Array([0x52, 0x49, 0x46, 0x46, 4, 0, 0, 0, 0x57, 0x45, 0x42, 0x50, 1, 2]);
const PNG = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
const USAGE = { input_tokens: 10014, output_tokens: 875, total_tokens: 10889 };
const KEY = "mk-test-0123456789";

interface Call {
  url: string;
  init: RequestInit;
}

function reply(status: number, body: unknown, requestId: string | null = "7b3f79b1"): { calls: Call[]; fetchFn: Fetch } {
  const calls: Call[] = [];
  const fetchFn: Fetch = async (url, init) => {
    calls.push({ url, init });
    const headers = requestId === null ? {} : { "x-request-id": requestId };
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers });
  };
  return { calls, fetchFn };
}

const ok = (bytes: Uint8Array) => ({ created: 1793737675, output_format: "webp", data: [{ b64_json: Buffer.from(bytes).toString("base64") }], usage: USAGE });

test.each([
  [{ MODEL_API_KEY: "a", META_API_KEY: "b" }, "a"],
  [{ META_API_KEY: "b" }, "b"],
  [{ MODEL_API_KEY: "", META_API_KEY: "b" }, "b"],
])("museKey reads the Meta key from the environment (%o)", (env, want) => {
  expect(museKey(env)).toBe(want);
});

test("museKey refuses an environment without a Meta key", () => {
  expect(() => museKey({ OPENAI_API_KEY: "x" })).toThrow("muse: set MODEL_API_KEY or META_API_KEY");
});

test("generate posts model, prompt and size as JSON with the bearer key", async () => {
  const { calls, fetchFn } = reply(200, ok(WEBP));
  const got = await generate("a booth", "1536x1024", KEY, fetchFn);
  expect(calls).toHaveLength(1);
  expect(calls[0]!.url).toBe("https://api.meta.ai/v1/images/generations");
  expect(calls[0]!.init.method).toBe("POST");
  expect(calls[0]!.init.headers).toEqual({ authorization: `Bearer ${KEY}`, "content-type": "application/json" });
  expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ model: "muse-image-1.0", prompt: "a booth", size: "1536x1024" });
  expect(got).toEqual({ endpoint: "/v1/images/generations", image: WEBP, requestId: "7b3f79b1", usage: USAGE });
});

test("edit sends the reference image, model and prompt as multipart", async () => {
  const { calls, fetchFn } = reply(200, ok(WEBP), "65c4c73e");
  const got = await edit("isolate the booth", PNG, "booth.png", KEY, fetchFn);
  expect(calls[0]!.url).toBe("https://api.meta.ai/v1/images/edits");
  expect(calls[0]!.init.headers).toEqual({ authorization: `Bearer ${KEY}` });
  const form = calls[0]!.init.body as FormData;
  expect([form.get("model"), form.get("prompt")]).toEqual(["muse-image-1.0", "isolate the booth"]);
  const file = form.get("image") as File;
  expect([file.name, file.type, Array.from(new Uint8Array(await file.arrayBuffer()))]).toEqual(["booth.png", "image/png", Array.from(PNG)]);
  expect([got.endpoint, got.requestId]).toEqual(["/v1/images/edits", "65c4c73e"]);
});

test("an HTTP error names the status and never echoes the key", async () => {
  const { fetchFn } = reply(401, `{"error":"bad key ${KEY}"}`);
  const message = await generate("a booth", "1024x1024", KEY, fetchFn).then(
    () => "resolved",
    (e: Error) => e.message,
  );
  expect(message).toMatch(/^muse: HTTP 401: /);
  expect(message).not.toContain(KEY);
});

test.each([
  ["no image", { data: [], usage: USAGE }, "muse: no image"],
  ["a PNG instead of WebP", ok(PNG), "muse: not a WebP image"],
  ["a body that is not JSON", "<html>busy</html>", "muse: no image"],
])("a 200 reply with %s is refused", async (_name, body, message) => {
  const { fetchFn } = reply(200, body);
  await expect(generate("a booth", "1024x1024", KEY, fetchFn)).rejects.toThrow(message);
});

test.each(["1024", "16:9", "1024x1024 ", "99x99"])("generate refuses size %j before any request", async (size) => {
  const { calls, fetchFn } = reply(200, ok(WEBP));
  await expect(generate("a booth", size, KEY, fetchFn)).rejects.toThrow("muse: bad size");
  expect(calls).toHaveLength(0);
});

test("a reply without a request id records none", async () => {
  const { fetchFn } = reply(200, ok(WEBP), null);
  expect((await generate("a booth", "1024x1024", KEY, fetchFn)).requestId).toBeNull();
});

test("provenance appends model, endpoint and request id to the prompt", () => {
  expect(provenance("a booth\n", { endpoint: "/v1/images/edits", requestId: "65c4c73e" })).toBe(
    "a booth\n\nmodel: muse-image-1.0\nendpoint: /v1/images/edits\nrequest-id: 65c4c73e\n",
  );
});
