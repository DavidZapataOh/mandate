export type Source = "desk" | "attack" | "hook" | "bill" | "deploy" | "bank";

export interface DecisionEvent {
  v: 1;
  id: string;
  ts: number;
  mode: string;
  verdict: string;
  action: string;
  policy: string;
  cert: string | null;
  reason: string;
  lat_us: number;
}

export interface Attribution {
  provider: string;
  model: string;
  response_id: string | null;
  request_id: string | null;
  latency_ms: number | null;
  input_tokens: number | null;
  output_tokens: number | null;
  anchor: string | null;
}

export interface DeskSubject {
  step: "intent" | "quote" | "approve" | "confirm";
  quote_id: string | null;
  status: string;
  summary: string;
  payment_id: string | null;
  reason: string | null;
}

export interface AttackSubject {
  attack: string;
  layer: string;
  reason: string;
  blocked: boolean;
  moved_cents: number;
  narrative: string;
  origin: "template" | "model";
}

export interface HookSubject {
  agent: string;
  tool: string;
  targets: string[];
  tool_use_id: string | null;
}

export interface BillSubject {
  proposal_call_id: string;
  summary: string;
  confirmation: string | null;
  report_error: string | null;
}

export interface DeploySubject {
  step: "release" | "poisoned_tool" | "stale_migration";
  agent: string;
  summary: string;
  layer: string;
  reason: string;
  blocked: boolean;
}

/** What the bank itself reported: one event from its own event list. */
export interface BankSubject {
  rail: "sandbox";
  event_id: string;
  category: string;
  object_type: string;
  object_id: string;
  created_at: string;
  summary: string;
}

export interface RegistryProof {
  seq: number;
  root: string;
  leaves: number;
  leaf: string;
  siblings: string[];
}

export type Rail = "simulated" | "sandbox";

export interface BankTransfer {
  rail: Rail;
  provider: string | null;
  transfer_id: string;
  status: string;
  idempotency_key: string | null;
}

export interface Forensic {
  cava: Record<string, unknown>;
  action_hash: string;
  policy: { policy_id: string; rule_id: string | null };
  cert_claims: Record<string, unknown> | null;
  consent: Record<string, unknown> | null;
  registry: RegistryProof | null;
  anchor: string | null;
  bank: BankTransfer | null;
}

export interface Hello {
  epoch: string;
  last_seq: number;
}

interface LineOf<S extends Source, T> {
  v: 3;
  seq: number;
  source: S;
  event: DecisionEvent | null;
  meta: Attribution | null;
  subject: T;
  forensic: Forensic | null;
}

export type ConsoleLine =
  | LineOf<"desk", DeskSubject>
  | LineOf<"attack", AttackSubject>
  | LineOf<"hook", HookSubject>
  | LineOf<"bill", BillSubject>
  | LineOf<"deploy", DeploySubject>
  | LineOf<"bank", BankSubject>;
