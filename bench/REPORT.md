# Mandate benchmarks

Measured 2026-11-04T23:59:16Z on Apple M4, 10 cores, macOS-27.0.1, Python 3.14.3, commit b54441e.
Each path ran three rounds after a warmup; each statistic is the median of its round values. Budgets: `bench/budgets.toml`. Reproduce: `python -m bench report --dist console/dist`.

## Headline

- Gate decision (`gate.shim.decide`): p50 10.1 µs, p95 10.3 µs, 98,617/s on one thread.
- Governed payment, gate and bank verifier (`gate.governed.run`): p50 143.1 µs, p95 152.4 µs, 6,957/s on one thread.
- Desk payment, quote to sealed receipt, durable (`desk.pay.durable`): p50 1,002.3 µs, p95 1,105.3 µs, 955/s on one thread.
- Template attacks that got past their layer: 0 of 2100; cents moved: 0 (`attacks.templates`, seven kinds on the simulated bank).

## In process: one thread, fixed inputs

| Path | Samples | p50 µs | p95 µs | per s |
|---|---:|---:|---:|---:|
| gate.cava.hash | 6000 | 3.4 | 3.6 | 280,089 |
| gate.cava.commit | 6000 | 5.0 | 5.4 | 192,933 |
| gate.policy.evaluate | 6000 | 1.3 | 1.4 | 688,933 |
| gate.certs.verify | 6000 | 69.4 | 74.7 | 14,427 |
| gate.shim.decide | 6000 | 10.1 | 10.3 | 98,617 |
| gate.approval.verify | 6000 | 42.5 | 45.3 | 23,541 |
| gate.consent.check | 6000 | 85.9 | 91.3 | 11,596 |
| gate.consent.find_holder | 1500 | 653.3 | 674.4 | 1,537 |
| gate.governed.run | 3000 | 143.1 | 152.4 | 6,957 |
| desk.pay.memory | 180 | 674.9 | 694.2 | 1,480 |
| registry.append_seal | 180 | 40.0 | 40.9 | 24,727 |
| registry.prove | 180 | 7.0 | 7.2 | 138,368 |
| receipt.verify | 6000 | 174.0 | 184.1 | 5,704 |
| desk.reconcile | 60 | 4,867.8 | 5,038.2 | 205 |
| desk.receipt_by_hash | 6000 | 14.8 | 15.2 | 67,658 |
| attacks.templates | 300 | 1,004.5 | 1,066.9 | 990 |

## Local disk: in process, SQLite state store, synchronous=FULL

| Path | Samples | p50 µs | p95 µs | per s |
|---|---:|---:|---:|---:|
| desk.pay.durable | 180 | 1,002.3 | 1,105.3 | 955 |
| state.reopen | 9 | 14,510.6 | 14,789.8 | 69 |

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
