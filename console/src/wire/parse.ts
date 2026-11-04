import type { ConsoleLine, Hello, Source } from "./types";

export class WireError extends Error {}

type Obj = Record<string, unknown>;
type Check = (value: unknown) => boolean;

const isObj = (value: unknown): value is Obj =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const str: Check = (value) => typeof value === "string";
const bool: Check = (value) => typeof value === "boolean";
const int: Check = (value) => Number.isSafeInteger(value);
const num: Check = (value) => typeof value === "number" && Number.isFinite(value);
const nullable =
  (check: Check): Check =>
  (value) =>
    value === null || check(value);
const strings: Check = (value) => Array.isArray(value) && value.every(str);
const oneOf =
  (...allowed: string[]): Check =>
  (value) =>
    typeof value === "string" && allowed.includes(value);

// A shape check: exactly these keys, each passing its own check.
function shape(spec: Record<string, Check>): Check {
  const keys = Object.keys(spec);
  return (value) =>
    isObj(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => key in value && spec[key]?.(value[key]) === true);
}

const EVENT = shape({
  v: (value) => value === 1,
  id: str,
  ts: int,
  mode: str,
  verdict: str,
  action: str,
  policy: str,
  cert: nullable(str),
  reason: str,
  lat_us: num,
});

const META = shape({
  provider: str,
  model: str,
  response_id: nullable(str),
  request_id: nullable(str),
  latency_ms: nullable(num),
  input_tokens: nullable(int),
  output_tokens: nullable(int),
  anchor: nullable(str),
});

const REGISTRY = shape({ seq: int, root: str, leaves: int, leaf: str, siblings: strings });

const BANK = shape({
  rail: oneOf("simulated", "sandbox"),
  provider: nullable(str),
  transfer_id: str,
  status: str,
  idempotency_key: nullable(str),
});

const FORENSIC = shape({
  cava: isObj,
  action_hash: str,
  policy: shape({ policy_id: str, rule_id: nullable(str) }),
  cert_claims: nullable(isObj),
  consent: nullable(isObj),
  registry: nullable(REGISTRY),
  anchor: nullable(str),
  bank: nullable(BANK),
});

const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const SUBJECTS: Record<Source, Check> = {
  desk: shape({
    step: oneOf("intent", "quote", "approve", "confirm", "settle"),
    quote_id: nullable(str),
    status: str,
    summary: str,
    payment_id: nullable(str),
    reason: nullable(str),
  }),
  attack: shape({
    attack: str,
    layer: str,
    reason: str,
    blocked: bool,
    moved_cents: int,
    narrative: str,
    origin: oneOf("template", "model"),
  }),
  hook: shape({ agent: str, tool: str, targets: strings, tool_use_id: nullable(str) }),
  bill: shape({
    proposal_call_id: str,
    summary: str,
    confirmation: nullable(str),
    report_error: nullable(str),
  }),
  deploy: shape({
    step: oneOf("release", "poisoned_tool", "stale_migration"),
    agent: str,
    summary: str,
    layer: str,
    reason: str,
    blocked: bool,
  }),
  bank: shape({
    rail: oneOf("sandbox"),
    event_id: str,
    category: str,
    object_type: str,
    object_id: str,
    created_at: (value) => typeof value === "string" && UTC_SECONDS.test(value),
    summary: str,
  }),
};

const LINE_KEYS = ["v", "seq", "source", "event", "meta", "subject", "forensic"];

function decode(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new WireError("wire: not JSON");
  }
}

/** Parse one v3 console line, rejecting anything that deviates from the wire. */
export function parseLine(text: string): ConsoleLine {
  const value = decode(text);
  if (!isObj(value)) throw new WireError("wire: not a line");
  const { source } = value;
  const valid =
    Object.keys(value).length === LINE_KEYS.length &&
    LINE_KEYS.every((key) => key in value) &&
    value.v === 3 &&
    typeof value.seq === "number" &&
    Number.isSafeInteger(value.seq) &&
    value.seq >= 1 &&
    oneOf("desk", "attack", "hook", "bill", "deploy", "bank")(source) &&
    nullable(EVENT)(value.event) &&
    nullable(META)(value.meta) &&
    SUBJECTS[source as Source](value.subject) &&
    nullable(FORENSIC)(value.forensic) &&
    // The bank's own report carries no gate decision, model call or evidence of ours.
    (source !== "bank" || (value.event === null && value.meta === null && value.forensic === null));
  if (!valid) throw new WireError("wire: malformed line");
  return value as unknown as ConsoleLine;
}

/** Parse the `hello` frame that opens an event stream. */
export function parseHello(text: string): Hello {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new WireError("wire: malformed hello");
  }
  const lastSeq = isObj(value) ? value.last_seq : undefined;
  if (
    !shape({ epoch: str, last_seq: int })(value) ||
    typeof lastSeq !== "number" ||
    lastSeq < 0
  ) {
    throw new WireError("wire: malformed hello");
  }
  return value as unknown as Hello;
}
