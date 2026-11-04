# Mandate benchmarks

Measured 2026-11-04T23:40:56Z on Apple M4, 10 cores, macOS-27.0.1, Python 3.14.3, commit 42f7c8b-dirty.
Each path ran three rounds after a warmup; each statistic is the median of its round values. Budgets: `bench/budgets.toml`. Reproduce: `python -m bench report --dist console/dist`.

## Headline

- Gate decision (`gate.shim.decide`): p50 10.2 µs, p95 10.5 µs, 95,426/s on one thread.
- Governed payment, gate and bank verifier (`gate.governed.run`): p50 147.0 µs, p95 158.2 µs, 6,530/s on one thread.
- Desk payment, quote to sealed receipt, durable (`desk.pay.durable`): p50 1,053.5 µs, p95 1,196.4 µs, 911/s on one thread.
- Template attacks that got past their layer: 0 of 2100; cents moved: 0 (`attacks.templates`, seven kinds on the simulated bank).

## In process: one thread, fixed inputs

| Path | Samples | p50 µs | p95 µs | per s |
|---|---:|---:|---:|---:|
| gate.cava.hash | 6000 | 3.5 | 3.5 | 272,963 |
| gate.cava.commit | 6000 | 5.2 | 12.0 | 164,232 |
| gate.policy.evaluate | 6000 | 2.8 | 3.0 | 377,944 |
| gate.certs.verify | 6000 | 71.2 | 75.0 | 13,525 |
| gate.shim.decide | 6000 | 10.2 | 10.5 | 95,426 |
| gate.approval.verify | 6000 | 43.1 | 43.8 | 22,943 |
| gate.consent.check | 6000 | 88.3 | 272.7 | 9,517 |
| gate.consent.find_holder | 1500 | 665.8 | 695.9 | 1,477 |
| gate.governed.run | 3000 | 147.0 | 158.2 | 6,530 |
| desk.pay.memory | 180 | 689.2 | 732.8 | 1,432 |
| registry.append_seal | 180 | 40.7 | 42.3 | 24,179 |
| registry.prove | 180 | 7.1 | 7.3 | 136,843 |
| receipt.verify | 6000 | 176.0 | 410.2 | 4,945 |
| desk.reconcile | 60 | 5,142.9 | 5,296.2 | 194 |
| desk.receipt_by_hash | 6000 | 15.3 | 30.1 | 56,793 |
| attacks.templates | 300 | 995.2 | 1,049.9 | 995 |

## Local disk: in process, SQLite state store, synchronous=FULL

| Path | Samples | p50 µs | p95 µs | per s |
|---|---:|---:|---:|---:|
| desk.pay.durable | 180 | 1,053.5 | 1,196.4 | 911 |
| state.reopen | 9 | 15,085.0 | 15,107.2 | 67 |

## Console build: gzip -9 bytes

| Asset | Bytes |
|---|---:|
| console.command | 23,771 |
| console.explorer | 20,788 |
| console.holder | 9,172 |
| console.index | 27,943 |
| console.lazy | 1,013,352 |

## Live: sandbox, network dependent

Owner-run jobs, never part of the gate's numbers above; each row shows when it ran.

| Path | Provider | Measured | Samples | p50 ms | p95 ms | max ms | Includes |
|---|---|---|---:|---:|---:|---:|---|
| ots.stamp | opentimestamps | 2026-11-04T23:40:22Z | 3 | 4,355.3 | 4,867.4 | 4,924.3 | one seal root sent to the four aggregators |
| ots.verify | opentimestamps + blockstream | 2026-11-04T23:40:34Z | 3 | 2,347.7 | 2,812.0 | 2,863.5 | upgrade of the recorded confirmed proof, block header fetch and offline check |
| sandbox.governed_payment | increase | 2026-11-04T23:40:03Z | 5 | 357.1 | 383.3 | 389.0 | gate decision, certificate, bank verifier and one Increase account transfer, from this machine |
| sandbox.reconcile | increase | 2026-11-04T23:40:07Z | 5 | 397.1 | 400.1 | 400.4 | one reconciliation round: list the debit account's transfers since genesis and compare with the sealed receipts |
| zktls.prove | increase + local notary | 2026-11-04T23:40:10Z | 2 | 1,414.8 | 1,833.8 | 1,880.3 | holder-side MPC-TLS session with the sandbox through Mandate's notary, then the presentation |
| zktls.verify | local verifier binary | 2026-11-04T23:40:13Z | 10 | 5.1 | 6.0 | 6.4 | mandate-zktls verify on one captured presentation; local subprocess, no network |

## Breaches

No breaches.
