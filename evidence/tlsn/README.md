# zkTLS evidence (tlsn)

One real zkTLS attestation, end to end, using the tlsn reference
implementation unmodified: prove, present, verify.

The live test (`evidence/test_tlsn_live.py`) drives the documented
commands directly. There is no shipped wrapper.

## Setup (one time)

```bash
git clone https://github.com/tlsnotary/tlsn.git --branch v0.1.0-alpha.14
cd tlsn
cargo build --release --examples
export TLSN_DIR=$PWD
```

Release is mandatory: debug is too slow and the TLS session times out.
First build takes 15+ minutes.

## Contract

- `TLSN_DIR` points at a tlsn checkout at tag `v0.1.0-alpha.14`.
- `cargo` is on PATH.
- TCP `127.0.0.1:4000` is free for the fixture.

## Commands the test drives

Fixture (cwd `TLSN_DIR`):

```bash
PORT=4000 cargo run --release --bin tlsn-server-fixture
```

Prove, present, verify (cwd `TLSN_DIR`, in order):

```bash
SERVER_PORT=4000 cargo run --release --example attestation_prove
cargo run --release --example attestation_present
cargo run --release --example attestation_verify
```

Expected markers: `Notarization completed successfully!`,
`Presentation built successfully!`, `Successfully verified` plus
`John Doe`; plus a non-empty `example-json.presentation.tlsn`
artifact under `TLSN_DIR`.

## Run

```bash
TLSN_DIR=<checkout> mandate/.venv/bin/pytest mandate/evidence/test_tlsn_live.py -v -m live
```

Without `TLSN_DIR` the live test skips cleanly.

## Seam statement

The proof attests the documented example JSON from
`tlsn-server-fixture` (endpoint `tlsn-server-fixture`, content
`example-json`); bank truth comes from the cooperative path; a bank
TLS endpoint with a custom attestor is future work, out of scope for this evidence.
