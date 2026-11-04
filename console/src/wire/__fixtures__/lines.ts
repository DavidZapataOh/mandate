// Test data only; the bundle gate fails the build if this marker ships.
export const MARKER = "MANDATE_FIXTURE";

export const CONFIRM =
  '{"v":3,"seq":3,"source":"desk","event":{"v":1,"id":"evt:00000000000000000000000000000002","ts":1800001000,"mode":"ENFORCE","verdict":"MET","action":"52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b","policy":"desk","cert":"00000000000000000000000000000002","reason":"rule pay-with-consent satisfied","lat_us":61.0},"meta":null,"subject":{"step":"confirm","quote_id":"q:000001","status":"confirmed","summary":"MANDATE_FIXTURE Pay 200.00 USD to acme-991 (ref A-991) from checking-881","payment_id":"pay:000001","reason":"ok: executed"},"forensic":{"cava":{"category":"payments","evidence_refs":["q:000001"],"executable":"bank.pay","freshness":{"nonce":"00000000000000000000000000000002","timestamp":1800001000},"operation":"transfer","reversible":false,"runtime":"mcp","targets":["amount:USD:20000","from:checking-881","ref:A-991","to:acme-991"],"version":"cava/1"},"action_hash":"52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b","policy":{"policy_id":"desk","rule_id":"pay-with-consent"},"cert_claims":{"action_hash":"52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b","policy_id":"desk","policy_version":1,"verdict":"MET","freshness_nonce":"00000000000000000000000000000002","scope":"mcp:bank.pay:transfer","reasoning_commitment":"6b1ae26a9ea91c2c54b03e36e874e2add2be9910e3bc8ed184a70fea39cf6b24","evidence_refs":["q:000001"],"revocation_index":1},"consent":{"amount_cents":20000,"currency":"USD","recipient":"acme-991","reference":"A-991","source":"checking-881","nonce":"00000000000000000000000000000001","expires_at":1800001600},"registry":{"seq":1,"root":"70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87","leaves":1,"leaf":"70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87","siblings":[]},"anchor":null}}';

export const ATTACK =
  '{"v":3,"seq":4,"source":"attack","event":{"v":1,"id":"evt:atk00000000000000000000000000003","ts":1800001000,"mode":"ENFORCE","verdict":"NOT_MET","action":"89f0357807b9d6e90a1c66d00e2a058ad97a5370349978a0ddceb67c50653f9a","policy":"payments","cert":null,"reason":"recipient differs from intent","lat_us":61.0},"meta":null,"subject":{"attack":"payee_swap","layer":"model->gate","reason":"recipient differs from intent","blocked":true,"moved_cents":0,"narrative":"MANDATE_FIXTURE Swap the payee of the approved 200.00 USD bill to evil-666.","origin":"template"},"forensic":{"cava":{"category":"payments","evidence_refs":[],"executable":"bank.pay","freshness":{"nonce":"atk00000000000000000000000000003","timestamp":1800001000},"operation":"transfer","reversible":false,"runtime":"muse","targets":["amount:USD:20000","from:checking-881","ref:A-991","to:evil-666"],"version":"cava/1"},"action_hash":"89f0357807b9d6e90a1c66d00e2a058ad97a5370349978a0ddceb67c50653f9a","policy":{"policy_id":"payments","rule_id":"pay-intent"},"cert_claims":null,"consent":null,"registry":null,"anchor":null}}';

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

/** The certified Nimbus release, byte for byte the Python golden deploy line. */
export const DEPLOY =
  '{"v":3,"seq":9,"source":"deploy","event":{"v":1,"id":"evt:dep00000000000000000000000000009","ts":1800001000,"mode":"ENFORCE","verdict":"MET","action":"1be9ccd395f38aeb073d15560b4bdc8bc07326b8457578c8d5db799b92ccaa01","policy":"nimbus","cert":"dep00000000000000000000000000009","reason":"rule release-api-v2 satisfied","lat_us":18.0},"meta":null,"subject":{"step":"release","agent":"nimbus-deploy","summary":"MANDATE_FIXTURE Deploy api-v2 to prod-eu","layer":"gate","reason":"ok: released","blocked":false},"forensic":{"cava":{"category":"deploy","evidence_refs":[],"executable":"nimbus","freshness":{"nonce":"dep00000000000000000000000000009","timestamp":1800001000},"operation":"deploy","reversible":false,"runtime":"muse-code","targets":["artifact:api-v2","env:prod-eu"],"version":"cava/1"},"action_hash":"1be9ccd395f38aeb073d15560b4bdc8bc07326b8457578c8d5db799b92ccaa01","policy":{"policy_id":"nimbus","rule_id":"release-api-v2"},"cert_claims":{"action_hash":"1be9ccd395f38aeb073d15560b4bdc8bc07326b8457578c8d5db799b92ccaa01","policy_id":"nimbus","policy_version":1,"verdict":"MET","freshness_nonce":"dep00000000000000000000000000009","scope":"nimbus:prod-eu","reasoning_commitment":"0000000000000000000000000000000000000000000000000000000000000000","evidence_refs":[],"revocation_index":0},"consent":null,"registry":null,"anchor":null}}';
