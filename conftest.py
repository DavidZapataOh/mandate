"""Shared pytest fixtures (lives outside packages, never shipped)."""

import itertools
import socket
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from bank.api import Bank
from bank.rail import BankRail
from bank.verifier import Verifier
from evidence.zktls import BankProofSetup
from gate.cava import CavaAction, Freshness
from gate.certs import CertClaims, generate_keypair, public_key_of
from gate.consent import Consent, HolderApproval, sign_approval
from gate.policy import Intent, Policy, Rule, Verdict
from gate.state import StateStore
from swarm.console_line import ConsoleLine
from swarm.desk import PaymentDesk
from swarm.intent import sign_intent


@pytest.fixture
def sample_action() -> CavaAction:
    return CavaAction(
        version="cava/1",
        runtime="mcp",
        executable="bank.pay",
        operation="transfer",
        category="payments",
        targets=(
            "acct:checking-881",
            "merchant:acme-991",
            "amount:USD:20000",
            "to:acme-991",
            "from:checking-881",
            "ref:A-991",
        ),
        reversible=False,
        freshness=Freshness(
            nonce="deadbeef00112233445566778899aabbcc", timestamp=1800000000
        ),
        evidence_refs=("ev:funds-proof-7f3a",),
    )


@pytest.fixture
def sample_intent() -> Intent:
    return Intent(
        amount_cents=20000,
        currency="USD",
        recipient="acme-991",
        reference="A-991",
    )


@pytest.fixture
def sample_policy() -> Policy:
    return Policy(
        policy_id="payments",
        version=1,
        rules=(
            Rule(
                rule_id="pay-exact",
                actor="mcp:bank.pay",
                operation="transfer",
                target="to:acme-991",
                amount_exact=True,
                amount_lte_cents=None,
                approval_required=False,
            ),
        ),
    )


@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def cert_claims() -> CertClaims:
    return CertClaims(
        action_hash="5393e9fa493501ae0f5a7247bd5e8c6722b37d05996e2baab609ac920990002b",
        policy_id="payments",
        policy_version=1,
        verdict=Verdict.MET,
        freshness_nonce="deadbeef00112233445566778899aabbcc",
        issued_at=1800000000,
        expires_at=1800000300,
        scope="mcp:bank.pay:transfer",
        reasoning_commitment="b5" * 32,
        evidence_refs=("ev:funds-proof-7f3a",),
        revocation_index=7,
    )


DESK_NOW = 1800001000


def _keys(private: bytes | None) -> tuple[bytes, bytes]:
    if private is None:
        return generate_keypair()
    return (private, public_key_of(private))


@pytest.fixture
def make_desk() -> Callable[..., tuple[PaymentDesk, bytes | None]]:
    def build(
        register: bool = True,
        clock: Callable[[], int] | None = None,
        publish: Callable[[ConsoleLine], object] | None = None,
        gate_key: bytes | None = None,
        holder_key: bytes | None = None,
        intents: tuple[Intent, ...] = (),
        bank_key: bytes | None = None,
        require_intent: bool = False,
        bank: BankRail | None = None,
        zktls: BankProofSetup | None = None,
        state: StateStore | None = None,
    ) -> tuple[PaymentDesk, bytes | None]:
        gate_priv, gate_pub = _keys(gate_key)
        counter = itertools.count(1)
        salt = itertools.count(1)
        sd_salt = itertools.count(1)
        holder_number = itertools.count(1)
        desk = PaymentDesk(
            source="checking-881",
            bank=bank or Bank({"checking-881": 50000, "acme-991": 0}, state=state),
            verifier=Verifier(gate_pub, state=state),
            gate_key=gate_priv,
            clock=clock or (lambda: DESK_NOW),
            nonces=lambda: f"{next(counter):032x}",
            publish=publish,
            action_salts=lambda: bytes([next(salt)]) * 32,
            salts=lambda: bytes([next(sd_salt)]) * 16,
            bank_key=bank_key,
            require_intent=require_intent,
            zktls=zktls,
            state=state,
            holder_ids=lambda: f"h:{next(holder_number):016x}",
        )
        if not register:
            return desk, None
        holder_priv, holder_pub = _keys(holder_key)
        desk.register_holder(holder_pub)
        for intent in intents:
            desk.record_intent(intent, sign_intent(holder_priv, intent))
        return desk, holder_priv

    return build


@pytest.fixture
def sign_quote() -> Callable[[bytes, dict[str, Any]], HolderApproval]:
    one_time = itertools.count(0x81)

    def sign(holder_priv: bytes, quoted: dict[str, Any]) -> HolderApproval:
        unsigned = Consent(**quoted["consent"], signature=b"")
        seed = bytes([next(one_time)]) * 32
        return sign_approval(holder_priv, unsigned, seed)

    return sign


@pytest.fixture
def state_store(tmp_path: Path) -> Iterator[StateStore]:
    store = StateStore(tmp_path / "state" / "state.db")
    yield store
    store.close()


@pytest.fixture
def serve() -> Iterator[Callable[[Any], str]]:
    servers: list[tuple[uvicorn.Server, threading.Thread]] = []

    def start(app: Any) -> str:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
        thread = threading.Thread(
            target=server.run, kwargs={"sockets": [sock]}, daemon=True
        )
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("server did not start")
            time.sleep(0.02)
        servers.append((server, thread))
        return f"http://127.0.0.1:{port}"

    yield start
    for server, thread in servers:
        server.should_exit = True
        thread.join(5)
