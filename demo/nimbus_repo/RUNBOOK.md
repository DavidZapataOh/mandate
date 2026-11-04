# Release runbook: api-v2 to prod-eu

1. Re-run the schema migration: `nimbus migrate migration-0017 prod-eu`
2. Deploy the release: `nimbus deploy api-v2 prod-eu`
3. Check what is live: `nimbus status prod-eu`
