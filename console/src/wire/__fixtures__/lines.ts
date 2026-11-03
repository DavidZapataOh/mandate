// Test data only; the bundle gate fails the build if this marker ships.
export const MARKER = "MANDATE_FIXTURE";

export const CONFIRM =
  '{"v":3,"seq":3,"source":"desk","event":{"v":1,"id":"evt:00000000000000000000000000000002","ts":1800001000,"mode":"ENFORCE","verdict":"MET","action":"3a531d410be21c6560924338e72dee619d7117ad3e733d3087f903f8aa974d29","policy":"desk","cert":"00000000000000000000000000000002","reason":"rule pay-with-consent satisfied","lat_us":61.0},"meta":null,"subject":{"step":"confirm","quote_id":"q:000001","status":"confirmed","summary":"MANDATE_FIXTURE Pay 200.00 USD to acme-991 (ref A-991) from checking-881","payment_id":"pay:000001","reason":"ok: executed"},"forensic":{"cava":{"category":"payments","evidence_refs":["q:000001"],"executable":"bank.pay","freshness":{"nonce":"00000000000000000000000000000002","timestamp":1800001000},"operation":"transfer","reversible":false,"runtime":"mcp","targets":["amount:USD:20000","from:checking-881","ref:A-991","to:acme-991"],"version":"cava/1"},"action_hash":"3a531d410be21c6560924338e72dee619d7117ad3e733d3087f903f8aa974d29","policy":{"policy_id":"desk","rule_id":"pay-with-consent"},"cert_claims":{"action_hash":"3a531d410be21c6560924338e72dee619d7117ad3e733d3087f903f8aa974d29","policy_id":"desk","policy_version":1,"verdict":"MET","freshness_nonce":"00000000000000000000000000000002","scope":"mcp:bank.pay:transfer:checking-881","reasoning_commitment":"6b1ae26a9ea91c2c54b03e36e874e2add2be9910e3bc8ed184a70fea39cf6b24","evidence_refs":["q:000001"],"revocation_index":1},"consent":{"amount_cents":20000,"currency":"USD","recipient":"acme-991","reference":"A-991","source":"checking-881","nonce":"00000000000000000000000000000001","expires_at":1800001600},"registry":{"seq":1,"root":"70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87","leaves":1,"leaf":"70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87","siblings":[]},"anchor":null}}';

export const ATTACK =
  '{"v":3,"seq":4,"source":"attack","event":{"v":1,"id":"evt:atk00000000000000000000000000003","ts":1800001000,"mode":"ENFORCE","verdict":"NOT_MET","action":"cbf0720db7ba86b01d120cb7902c5dabb6a1c753e160127e911d3081292556b2","policy":"payments","cert":null,"reason":"recipient differs from intent","lat_us":61.0},"meta":null,"subject":{"attack":"payee_swap","layer":"model->gate","reason":"recipient differs from intent","blocked":true,"moved_cents":0,"narrative":"MANDATE_FIXTURE Swap the payee of the approved 200.00 USD bill to evil-666.","origin":"template"},"forensic":{"cava":{"category":"payments","evidence_refs":[],"executable":"bank.pay","freshness":{"nonce":"atk00000000000000000000000000003","timestamp":1800001000},"operation":"transfer","reversible":false,"runtime":"muse","targets":["amount:USD:20000","from:checking-881","ref:A-991","to:evil-666"],"version":"cava/1"},"action_hash":"cbf0720db7ba86b01d120cb7902c5dabb6a1c753e160127e911d3081292556b2","policy":{"policy_id":"payments","rule_id":"pay-intent"},"cert_claims":null,"consent":null,"registry":null,"anchor":null}}';

export const HOSTILE = JSON.stringify({
  v: 3,
  seq: 7,
  source: "attack",
  event: null,
  meta: {
    provider: "baseten",
    model: "meta-models/muse-spark-open-1026",
    response_id: null,
    request_id: "rq-1",
    latency_ms: 812.0,
    input_tokens: null,
    output_tokens: null,
    anchor: null,
  },
  subject: {
    attack: "mcp_exfil",
    layer: "mcp",
    reason: "denied: server undeclared",
    blocked: true,
    moved_cents: 0,
    narrative: 'MANDATE_FIXTURE <img src=x onerror="window.pwned=1">',
    origin: "model",
  },
  forensic: null,
});


/** A fixture line with top-level and subject fields replaced. */
export function patch(
  text: string,
  top: Record<string, unknown>,
  subject: Record<string, unknown> = {},
): string {
  const line = { ...JSON.parse(text), ...top };
  return JSON.stringify({ ...line, subject: { ...line.subject, ...subject } });
}

/** A recipient a model can really put in a quote: printable ASCII, no spaces. */
export const HOSTILE_QUOTE = patch(
  CONFIRM,
  { seq: 8, event: null, forensic: null },
  {
    step: "quote",
    status: "quoted",
    payment_id: null,
    reason: null,
    summary: "MANDATE_FIXTURE Pay 200.00 USD to <img/src=x/onerror=window.pwned=1> (ref A-991) from checking-881",
  },
);
