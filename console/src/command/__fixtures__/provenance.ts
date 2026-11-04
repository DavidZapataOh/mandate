// Test data only: the body `GET /api/provenance` returns after one paid quote.
export const SERVER_BODY = JSON.stringify({
  epoch: "MANDATE_FIXTURE-a1b2c3d4",
  window: { first_seq: 1, last_seq: 9, retained: 9 },
  registry: { root: "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87", leaves: 1 },
  policies: [
    {
      policy_id: "desk", version: 1,
      rules: [{ rule_id: "pay-with-consent", actor: "mcp:bank.pay", operation: "transfer", target: "*", amount_exact: true, amount_lte_cents: null, approval_required: false, consent_required: true }],
    },
    {
      policy_id: "payments", version: 1,
      rules: [{ rule_id: "pay-intent", actor: "muse:bank.pay", operation: "transfer", target: "*", amount_exact: true, amount_lte_cents: null, approval_required: false, consent_required: false }],
    },
    {
      policy_id: "nimbus", version: 1,
      rules: [
        { rule_id: "release-api-v2", actor: "muse-code:nimbus", operation: "deploy", target: "artifact:api-v2", amount_exact: false, amount_lte_cents: null, approval_required: false, consent_required: false },
        { rule_id: "migrate-0042", actor: "muse-code:nimbus", operation: "migrate", target: "artifact:migration-0042", amount_exact: false, amount_lte_cents: null, approval_required: false, consent_required: false },
      ],
    },
  ],
});
