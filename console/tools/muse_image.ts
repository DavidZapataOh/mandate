import { readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";

export const MUSE_MODEL = "muse-image-1.0";
const BASE = "https://api.meta.ai";

export type Fetch = (url: string, init: RequestInit) => Promise<Response>;
export type Endpoint = "/v1/images/generations" | "/v1/images/edits";

export interface MuseResult {
  readonly endpoint: Endpoint;
  readonly image: Uint8Array;
  readonly requestId: string | null;
  readonly usage: Readonly<Record<string, number>> | null;
}

/** Reads the Meta key in the same order as the Python client; an empty value counts as unset. */
export function museKey(env: Readonly<Record<string, string | undefined>>): string {
  const key = env["MODEL_API_KEY"] || env["META_API_KEY"];
  if (!key) throw new Error("muse: set MODEL_API_KEY or META_API_KEY");
  return key;
}

function isWebp(b: Uint8Array): boolean {
  const tag = (from: number, s: string) => s.split("").every((c, i) => b[from + i] === c.charCodeAt(0));
  return b.length >= 12 && tag(0, "RIFF") && tag(8, "WEBP");
}

async function send(endpoint: Endpoint, init: RequestInit, key: string, fetchFn: Fetch): Promise<MuseResult> {
  const res = await fetchFn(BASE + endpoint, init);
  const text = await res.text();
  if (!res.ok) throw new Error(`muse: HTTP ${res.status}: ${text.replaceAll(key, "***").slice(0, 200)}`);
  let body: { data?: { b64_json?: unknown }[]; usage?: unknown } | null = null;
  try {
    body = JSON.parse(text);
  } catch {
    body = null;
  }
  const b64 = body?.data?.[0]?.b64_json;
  if (typeof b64 !== "string" || b64 === "") throw new Error("muse: no image");
  const image = new Uint8Array(Buffer.from(b64, "base64"));
  if (!isWebp(image)) throw new Error("muse: not a WebP image");
  const usage = body?.usage && typeof body.usage === "object" ? (body.usage as Record<string, number>) : null;
  return { endpoint, image, requestId: res.headers.get("x-request-id"), usage };
}

/** Text-only generation; `size` is `<w>x<h>`. */
export async function generate(prompt: string, size: string, key: string, fetchFn: Fetch = fetch): Promise<MuseResult> {
  if (!/^[1-9]\d{2,3}x[1-9]\d{2,3}$/.test(size)) throw new Error("muse: bad size");
  const init: RequestInit = {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({ model: MUSE_MODEL, prompt, size }),
  };
  return send("/v1/images/generations", init, key, fetchFn);
}

/** Edit anchored on a reference image; the result keeps the reference's aspect. */
export async function edit(
  prompt: string,
  image: Uint8Array,
  name: string,
  key: string,
  fetchFn: Fetch = fetch,
): Promise<MuseResult> {
  const form = new FormData();
  form.set("model", MUSE_MODEL);
  form.set("prompt", prompt);
  form.set("image", new File([image as Uint8Array<ArrayBuffer>], name, { type: name.endsWith(".png") ? "image/png" : "" }));
  return send("/v1/images/edits", { method: "POST", headers: { authorization: `Bearer ${key}` }, body: form }, key, fetchFn);
}

/** The prompt followed by the model, endpoint and request id that produced the image. */
export function provenance(prompt: string, call: { endpoint: Endpoint; requestId: string | null }): string {
  return `${prompt.trimEnd()}\n\nmodel: ${MUSE_MODEL}\nendpoint: ${call.endpoint}\nrequest-id: ${call.requestId ?? "none"}\n`;
}

function flags(argv: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i];
    const value = argv[i + 1];
    if (!name?.startsWith("--") || value === undefined) throw new Error(`muse: bad argument ${name ?? ""}`);
    out[name.slice(2)] = value;
  }
  return out;
}

async function main(argv: readonly string[]): Promise<void> {
  const [mode, ...rest] = argv;
  const f = flags(rest);
  const need = (k: string): string => f[k] ?? (() => { throw new Error(`muse: missing --${k}`); })();
  const key = museKey(process.env);
  const promptFile = need("prompt-file");
  const prompt = readFileSync(promptFile, "utf8");
  const size = f["size"] ?? "1536x1024";
  let result: MuseResult;
  let reference: string | null = null;
  if (mode === "edit") {
    reference = need("image");
    result = await edit(prompt, readFileSync(reference), basename(reference), key);
  } else if (mode === "generate") {
    result = await generate(prompt, size, key);
  } else {
    throw new Error("muse: usage: edit|generate");
  }
  const out = need("out");
  writeFileSync(out, result.image);
  const record = {
    model: MUSE_MODEL,
    endpoint: result.endpoint,
    request_id: result.requestId,
    usage: result.usage,
    size: mode === "generate" ? size : null,
    reference,
    prompt_file: promptFile,
    provenance: provenance(prompt, result),
  };
  writeFileSync(need("record"), `${JSON.stringify(record, null, 2)}\n`);
  console.log(`wrote ${out} (request ${result.requestId ?? "none"})`);
}

if (import.meta.main) {
  main(process.argv.slice(2)).catch((e: unknown) => {
    console.log(e instanceof Error ? e.message : String(e));
    process.exit(1);
  });
}
