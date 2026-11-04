import base64
import hashlib
import json
import secrets
import time

import httpx2
import pytest

from bank.increase import IncreaseRail, ensure_accounts, sandbox_client
from bank.verifier import Verifier
from e2e.attack_world import approval_body, b64, unsigned
from e2e.test_bank_attacks import _tool
from e2e.test_increase_live import LIVE, SANDBOX_TRANSFER, _key
from gate.certs import generate_keypair, public_key_of
from gate.consent import sign_approval
from gate.policy import Intent
from gate.state import StateStore
from swarm.desk import PaymentDesk
from swarm.intent import sign_intent
from swarm.server import build_server

INTENT = {
    "amount_cents": 100,
    "currency": "USD",
    "recipient": LIVE[1],
    "reference": "A-991",
}
QUOTE = {
    "to_account": LIVE[1],
    "amount_cents": 100,
    "currency": "USD",
    "reference": "A-991",
    "intent_id": "i:000001",
}


def _served(serve, rail, gate_key, path, holder_pub=None):
    store = StateStore(path)
    desk = PaymentDesk(
        source=LIVE[0],
        bank=rail,
        verifier=Verifier(public_key_of(gate_key), state=store),
        gate_key=gate_key,
        clock=lambda: int(time.time()),
        nonces=lambda: secrets.token_hex(16),
        state=store,
    )
    if holder_pub is not None:
        desk.register_holder(holder_pub)
    return serve(build_server(desk, "pair-x").streamable_http_app()), store


def _jti(receipt):
    payload = receipt["certificate"].split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))["jti"]


def _pay(url, holder):
    quote = _tool(url, "quote_payment", QUOTE)
    approval = sign_approval(holder, unsigned(quote))
    httpx2.post(f"{url}/api/approve", json=approval_body(quote["quote_id"], approval))
    return _tool(url, "confirm_payment", {"quote_id": quote["quote_id"]})


@pytest.mark.live
def test_one_certified_sandbox_payment_survives_every_attack_and_a_restart(
    serve, tmp_path
):
    client = sandbox_client(_key())
    ensure_accounts(client, LIVE, LIVE[0], 1_000_000)
    rail = IncreaseRail.connect(client)
    gate_key, _ = generate_keypair()
    holder, holder_pub = generate_keypair()
    # The registry begins at the desk's clock in whole seconds; the next
    # second keeps earlier live runs out of its list.
    time.sleep(1 - time.time() % 1)
    url, store = _served(serve, rail, gate_key, tmp_path / "state.db", holder_pub)
    signed = httpx2.post(
        f"{url}/api/intent",
        json={
            "intent": INTENT,
            "signature": b64(sign_intent(holder, Intent(**INTENT))),
        },
    )
    assert signed.json()["status"] == "signed"
    paid = _pay(url, holder)
    assert (paid["status"], paid["reason"]) == ("confirmed", "ok: executed")
    transfer_id = paid["payment_id"]
    assert SANDBOX_TRANSFER.fullmatch(transfer_id)
    assert _tool(url, "confirm_payment", {"quote_id": paid["quote_id"]}) == paid
    again = _pay(url, holder)
    assert (again["status"], again["reason"]) == ("denied", "intent: already used")
    report = httpx2.post(f"{url}/api/reconcile", json={}).json()
    assert (report["transfers"], report["certified"], report["unbacked"]) == (
        1,
        1,
        [],
    )
    assert (report["missing"], report["error"]) == ([], None)
    auditor = httpx2.get(f"{url}/api/receipt/{transfer_id}").json()
    store.close()
    restarted, store = _served(serve, rail, gate_key, tmp_path / "state.db")
    try:
        assert httpx2.get(f"{restarted}/api/receipt/{transfer_id}").json() == auditor
        digest = hashlib.sha256(auditor["sd"].split("~")[0].encode()).hexdigest()
        found = httpx2.get(f"{restarted}/api/receipt/by-hash/{digest}")
        assert (found.status_code, found.json()) == (200, auditor)
        listed = client.account_transfers.list(
            idempotency_key=f"mandate-cert-{_jti(auditor)}"
        )
        assert [t.id for t in listed.data] == [transfer_id]
    finally:
        store.close()
