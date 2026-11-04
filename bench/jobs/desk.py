"""Desk, registry, receipt and attack paths on the simulated bank.

Seal and inclusion-proof cost depends on the registry's size, so every desk
and registry path runs on a log pre-filled to ``LOG_SIZE`` entries; a log
that grew while timed would measure its own growth.
"""

import itertools
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path

from bank.api import Bank
from bank.verifier import Verifier
from bench.job import IN_PROCESS, LOCAL_DISK, Job, Timed
from gate.certs import public_key_of
from gate.consent import Consent, sign_approval
from gate.registry import Registry
from gate.sdjwt import process
from gate.state import StateStore
from swarm.console import AttackRunner
from swarm.desk import PaymentDesk
from swarm.hub import EventHub
from swarm.receipt import RECEIPT_TYP, receipt_hashes
from swarm.redteam import AttackKind

GATE = b"\x11" * 32
HOLDER = b"\x22" * 32
NOW = 1800001000
LOG_SIZE = 1000
RECONCILED = 200
SOURCE = "checking-881"
PAYEE = "acme-991"
CENTS = 100
REF = "A-991"
_FILLER = '{"payment_id":null,"quote_id":"q:000000","reason":"x","status":"denied"}'


def _counted() -> Callable[[], int]:
    counter = itertools.count(1)
    return lambda: next(counter)


def _desk(state: StateStore | None = None) -> PaymentDesk:
    nonce, action_salt, salt, holder = _counted(), _counted(), _counted(), _counted()
    desk = PaymentDesk(
        source=SOURCE,
        bank=Bank({SOURCE: 10**15, PAYEE: 0}, state=state),
        verifier=Verifier(public_key_of(GATE), state=state),
        gate_key=GATE,
        clock=lambda: NOW,
        nonces=lambda: f"{nonce():032x}",
        action_salts=lambda: action_salt().to_bytes(32, "big"),
        salts=lambda: salt().to_bytes(16, "big"),
        state=state,
        holder_ids=lambda: f"h:{holder():016x}",
    )
    desk.register_holder(public_key_of(HOLDER))
    return desk


def _fill(registry: Registry, state: StateStore | None = None) -> None:
    def work() -> None:
        for _ in range(LOG_SIZE - registry.size()):
            registry.append("denial", _FILLER)
        registry.anchor(NOW)

    if state is None:
        work()
        return
    # A durable registry seals each append in the commit that wrote it.
    with state.transaction():
        work()


def _payer(desk: PaymentDesk) -> Callable[[], dict[str, int]]:
    seeds = itertools.count()

    def pay() -> dict[str, int]:
        quoted = desk.quote(PAYEE, CENTS, "USD", REF)
        unsigned = Consent(**quoted["consent"], signature=b"")
        seed = (next(seeds) + 2**200).to_bytes(32, "big")
        desk.approve(quoted["quote_id"], sign_approval(HOLDER, unsigned, seed))
        status = desk.confirm(quoted["quote_id"])["status"]
        return {"ops": 1, "unpaid": int(status != "confirmed")}

    return pay


def _paid(desk: PaymentDesk, count: int) -> PaymentDesk:
    pay = _payer(desk)
    for _ in range(count):
        if pay()["unpaid"]:
            raise ValueError("bench: a setup payment did not pay")
    return desk


def _store(path: Path, stack: ExitStack) -> StateStore:
    path.parent.mkdir(parents=True, exist_ok=True)
    store = StateStore(path)
    stack.callback(store.close)
    return store


def _pay_memory(_scratch: Path, _stack: ExitStack) -> Timed:
    desk = _desk()
    _fill(desk.registry)
    return _payer(desk)


def _pay_durable(scratch: Path, stack: ExitStack) -> Timed:
    store = _store(scratch / "pay" / "state.db", stack)
    desk = _desk(store)
    _fill(desk.registry, store)
    return _payer(desk)


def _registry() -> Registry:
    registry = Registry(keypair=(GATE, public_key_of(GATE)))
    _fill(registry)
    return registry


def _append_seal(_scratch: Path, _stack: ExitStack) -> Timed:
    registry = _registry()
    ts = itertools.count(NOW + 1)

    def timed() -> dict[str, int]:
        registry.append("denial", _FILLER)
        registry.anchor(next(ts))
        return {"ops": 1}

    return timed


def _prove(_scratch: Path, _stack: ExitStack) -> Timed:
    registry = _registry()

    def timed() -> dict[str, int]:
        registry.prove(LOG_SIZE // 2)
        return {"ops": 1}

    return timed


def _receipt_verify(_scratch: Path, _stack: ExitStack) -> Timed:
    desk = _paid(_desk(), 1)
    receipt = desk.proof_receipt("pay:000001")
    if receipt is None:
        raise ValueError("bench: no receipt")
    sd, public = receipt["sd"], desk.gate_public_key

    def timed() -> dict[str, int]:
        _, reason = process(sd, public, RECEIPT_TYP)
        return {"ops": 1, "refused": int(reason != "ok: verified")}

    return timed


def _reconcile(_scratch: Path, _stack: ExitStack) -> Timed:
    desk = _paid(_desk(), RECONCILED)

    def timed() -> dict[str, int]:
        view = desk.reconcile().view()
        return {"ops": 1, "unbacked": len(view["unbacked"])}

    return timed


def _receipt_by_hash(_scratch: Path, _stack: ExitStack) -> Timed:
    desk = _paid(_desk(), RECONCILED)
    receipt = desk.proof_receipt("pay:000100")
    if receipt is None:
        raise ValueError("bench: no receipt")
    digest = receipt_hashes(receipt)[0]

    def timed() -> dict[str, int]:
        found = desk.receipt_by_hash(digest)
        return {"ops": 1, "missed": int(found is None)}

    return timed


def _reopen(scratch: Path, _stack: ExitStack) -> Timed:
    path = scratch / "reopen" / "state.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    store = StateStore(path)
    try:
        _paid(_desk(store), RECONCILED)
    finally:
        store.close()

    def timed() -> dict[str, int]:
        again = StateStore(path)
        try:
            _desk(again)
        finally:
            again.close()
        return {"ops": 1}

    return timed


def _attacks(_scratch: Path, _stack: ExitStack) -> Timed:
    nonce = _counted()
    runner = AttackRunner(
        _desk(), GATE, EventHub(), lambda: NOW, lambda: f"atk{nonce():029x}"
    )

    def timed() -> dict[str, int]:
        lines = [runner.run(kind) for kind in AttackKind]
        return {
            "attempts": len(lines),
            "unblocked": sum(not line.subject["blocked"] for line in lines),
            "moved_cents": sum(line.subject["moved_cents"] for line in lines),
        }

    return timed


DESK_JOBS: tuple[Job, ...] = (
    Job("desk.pay.memory", IN_PROCESS, _pay_memory, 60, 6),
    Job("desk.pay.durable", LOCAL_DISK, _pay_durable, 60, 6),
    Job("registry.append_seal", IN_PROCESS, _append_seal, 60, 6),
    Job("registry.prove", IN_PROCESS, _prove, 60, 6),
    Job("receipt.verify", IN_PROCESS, _receipt_verify, 2000, 200),
    Job("desk.reconcile", IN_PROCESS, _reconcile, 20, 2),
    Job("desk.receipt_by_hash", IN_PROCESS, _receipt_by_hash, 2000, 200),
    Job("state.reopen", LOCAL_DISK, _reopen, 3, 1),
    Job("attacks.templates", IN_PROCESS, _attacks, 100, 10),
)
