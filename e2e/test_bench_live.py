import os
import secrets
import time
from pathlib import Path

import pytest
from opentimestamps.calendar import RemoteCalendar

from bank.card import CARD_DEADLINE_S, agent_card
from bank.increase import IncreaseRail, ensure_accounts, sandbox_client
from bank.verifier import Verifier
from bench.live import save_live, time_live
from e2e.test_increase_live import LIVE, _governed, _key
from e2e.test_zktls_live import _presentation, live_desk  # noqa: F401
from evidence.zktls import run_verifier
from gate.anchor_public import (
    AGGREGATORS,
    NONCE_LEN,
    EsploraHeaders,
    attested_heights,
    confirm,
    stamp,
    upgrade,
)
from gate.certs import generate_keypair
from gate.conftest import OTS, unb64
from gate.consent import Consent, sign_approval
from gate.policy import Intent
from gate.state import StateStore
from swarm.desk import PaymentDesk
from swarm.intent import sign_intent

LIVE_DIR = Path(__file__).resolve().parent.parent / "bench" / "live"
CARD_APPROVED_ENV = "MANDATE_CARD_APPROVED_QUOTES"
CARD_URL_ENV = "MANDATE_CARD_WEBHOOK_URL"


@pytest.mark.live
def test_sandbox_payment_round_trip():
    client = sandbox_client(_key())
    ensure_accounts(client, LIVE, LIVE[0], 1_000_000)
    rail = IncreaseRail.connect(client)
    gate_key, gate_pub = generate_keypair()
    verifier, reasons = Verifier(gate_pub), []

    def pay():
        result, _, _ = _governed(rail, verifier, gate_key, 100)
        reasons.append(result.reason)

    result = time_live(
        "sandbox.governed_payment",
        "increase",
        "gate decision, certificate, bank verifier and one Increase account "
        "transfer, from this machine",
        pay,
        5,
    )
    assert reasons == ["ok: executed"] * 5
    save_live(result, LIVE_DIR)


@pytest.mark.live
def test_sandbox_reconcile_round(tmp_path):
    client = sandbox_client(_key())
    ensure_accounts(client, LIVE, LIVE[0], 1_000_000)
    gate_key, gate_pub = generate_keypair()
    holder_key, holder_pub = generate_keypair()
    store = StateStore(tmp_path / "state.db")
    # The registry begins at the desk's clock in whole seconds; the next
    # second keeps earlier tests' transfers out of its list.
    time.sleep(1 - time.time() % 1)
    desk = PaymentDesk(
        source=LIVE[0],
        bank=IncreaseRail.connect(client),
        verifier=Verifier(gate_pub, state=store),
        gate_key=gate_key,
        clock=lambda: int(time.time()),
        nonces=lambda: secrets.token_hex(16),
        state=store,
    )
    desk.register_holder(holder_pub)
    intent = Intent(100, "USD", LIVE[1], "A-991")
    recorded = desk.record_intent(intent, sign_intent(holder_key, intent))
    quoted = desk.quote(LIVE[1], 100, "USD", "A-991", recorded["intent_id"])
    consent = Consent(**quoted["consent"], signature=b"")
    desk.approve(quoted["quote_id"], sign_approval(holder_key, consent))
    assert desk.confirm(quoted["quote_id"])["reason"] == "ok: executed"
    views = []
    result = time_live(
        "sandbox.reconcile",
        "increase",
        "one reconciliation round: list the debit account's transfers since "
        "genesis and compare with the sealed receipts",
        lambda: views.append(desk.reconcile().view()),
        5,
    )
    assert [(v["error"], v["unbacked"], v["certified"]) for v in views] == [
        (None, [], 1)
    ] * 5
    store.close()
    save_live(result, LIVE_DIR)


def _charge(client, card_id, outcomes):
    def charge():
        answer = client.simulations.card_authorizations.create(
            amount=20000,
            card_id=card_id,
            merchant_acceptor_id="acme-991",
            merchant_descriptor="ACME 991",
        )
        outcomes.append(answer.pending_transaction is not None)

    return charge


@pytest.mark.live
def test_card_answers_inside_the_deadline():
    client = sandbox_client(_key())
    # Without the tunnel no webhook reaches Mandate and the bank times out.
    if not os.environ.get(CARD_URL_ENV):
        pytest.skip(f"live: open the card tunnel and set {CARD_URL_ENV}")
    rail = IncreaseRail.connect(client)
    card_id = agent_card(client, rail.account_id("checking-881"))
    if card_id is None:
        pytest.skip("live: run mandate-bank-setup --card-webhook-url first")
    approved = int(os.environ.get(CARD_APPROVED_ENV, "0"))
    outcomes = []
    if approved:
        ok = time_live(
            "sandbox.card_approve",
            "increase",
            "as card_decline, for a holder-approved quote: gate, certificate "
            "and the approve action inside the 4 s deadline",
            _charge(client, card_id, outcomes),
            approved,
        )
        assert outcomes == [True] * approved
        assert ok.max_ms < CARD_DEADLINE_S * 1000
        save_live(ok, LIVE_DIR)
    outcomes.clear()
    declined = time_live(
        "sandbox.card_decline",
        "increase",
        "Increase card authorization simulation through the tunnel to "
        "Mandate's webhook; no approved quote, so Mandate declines",
        _charge(client, card_id, outcomes),
        5,
    )
    assert outcomes == [False] * 5
    assert declined.max_ms < CARD_DEADLINE_S * 1000
    save_live(declined, LIVE_DIR)


@pytest.mark.live
def test_zktls_prove_and_verify(live_desk):  # noqa: F811
    desk, binary, _ = live_desk
    made = []
    proved = time_live(
        "zktls.prove",
        "increase + local notary",
        "holder-side MPC-TLS session with the sandbox through Mandate's "
        "notary, then the presentation",
        lambda: made.append(_presentation(desk, binary)),
        2,
    )
    verified = time_live(
        "zktls.verify",
        "local verifier binary",
        "mandate-zktls verify on one captured presentation; local "
        "subprocess, no network",
        lambda: run_verifier(binary, made[-1]),
        10,
    )
    save_live(proved, LIVE_DIR)
    save_live(verified, LIVE_DIR)


@pytest.mark.live
def test_public_timestamps_stamp_and_verify():
    calendars = [RemoteCalendar(url) for url in AGGREGATORS]
    proofs = []
    stamped = time_live(
        "ots.stamp",
        "opentimestamps",
        "one seal root sent to the four aggregators",
        lambda: proofs.extend(
            stamp([os.urandom(32)], calendars, lambda: os.urandom(NONCE_LEN))
        ),
        3,
    )
    assert len(proofs) == 3
    save_live(stamped, LIVE_DIR)
    golden = OTS["golden"]
    if not golden.get("confirmed"):
        pytest.skip("live: the golden stamp is not confirmed yet")
    proof, height = unb64(golden["confirmed"]), golden["bitcoin"]["height"]
    digest = bytes.fromhex(golden["digest"])

    def verify():
        upgraded = upgrade(proof)
        header = EsploraHeaders().header(attested_heights(upgraded)[0])
        confirm(upgraded, digest, height, header)

    verified = time_live(
        "ots.verify",
        "opentimestamps + blockstream",
        "upgrade of the recorded confirmed proof, block header fetch and offline check",
        verify,
        3,
    )
    save_live(verified, LIVE_DIR)
