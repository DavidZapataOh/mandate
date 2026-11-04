"""Mandate console: desk, event hub, template attacks, Nimbus steps, console."""

import argparse
import itertools
import json
import os
import secrets
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import FrameType
from typing import Any

import uvicorn
from increase import AuthenticationError, IncreaseError, PermissionDeniedError

from bank.api import Bank
from bank.credentials import BANK_KEY_ENV, take_bank_key
from bank.increase import IncreaseRail, sandbox_client
from bank.rail import BankRail
from bank.verifier import Verifier
from gate.certs import generate_keypair, public_key_of
from gate.policy import Intent
from gate.shim import RawCall
from swarm.attacker import AttackerTrace
from swarm.console_line import ConsoleLine, attack_line, deploy_line
from swarm.desk import PaymentDesk
from swarm.hub import EventHub
from swarm.intake import IntentIntake
from swarm.intent import IntentError, PayeeBook
from swarm.journal_tail import JournalTail
from swarm.live_attack import live_attacker
from swarm.meta_client import MetaClient, api_key_from_env
from swarm.nimbus import NimbusStep, ProdTarget, run_step
from swarm.redteam import TEMPLATES, AttackKind, AttackPlan, apply_attack
from swarm.server import build_server
from swarm.voice import transcribe, transcriber_from_env

CONSOLE_DIST = Path(__file__).resolve().parent.parent / "console" / "dist"
DEMO_PAYEES = Path(__file__).resolve().parent.parent / "demo" / "payees.json"
_DEMO_BALANCE_CENTS = 10000000
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
_GRACEFUL_SHUTDOWN_S = 2
_INTENT = Intent(
    amount_cents=20000, currency="USD", recipient="acme-991", reference="A-991"
)


def _legit_call(source: str) -> RawCall:
    return RawCall(
        runtime="muse",
        executable="bank.pay",
        operation="transfer",
        args=(
            ("amount", "20000"),
            ("currency", "USD"),
            ("from", source),
            ("to", "acme-991"),
            ("ref", "A-991"),
        ),
        category="payments",
        evidence_refs=(),
        reversible=False,
    )


def _now() -> int:
    return int(time.time())


def _nonce() -> str:
    return secrets.token_hex(16)


def counted_nonces(prefix: str) -> Callable[[], str]:
    """Build a nonce source that counts up from 1.

    A counter makes the n-th press the same action after every restart. The
    prefix is never hex, so these nonces cannot collide with the desk's.

    Args:
        prefix: Letters that open every nonce.

    Returns:
        A function giving ``prefix`` plus a 29-digit counter on each call.
    """
    count = itertools.count(1)
    return lambda: f"{prefix}{next(count):029d}"


class AttackRunner:
    """Applies the pinned template attacks to a simulated bank.

    Attacks draw counted nonces, which repeat across restarts, so they never
    reach a real rail: they run against a simulated bank under the desk's
    verifier and lock.

    Args:
        desk: Desk whose verifier and lock the attacks run under.
        gate_key: Raw Ed25519 private key the gate signs with.
        hub: Hub that receives the attack lines.
        clock: Current unix time in seconds.
        nonces: Source of unique freshness nonces.
        salts: Source of 32-byte action salts, one per press; None lets the
            gate draw them from the operating system.
        bank: Simulated bank the attacks move money on; None uses the
            desk's bank, which must then be simulated.

    Raises:
        ValueError: If no bank is given and the desk's bank is not simulated.
    """

    def __init__(
        self,
        desk: PaymentDesk,
        gate_key: bytes,
        hub: EventHub,
        clock: Callable[[], int],
        nonces: Callable[[], str],
        salts: Callable[[], bytes] | None = None,
        bank: Bank | None = None,
    ) -> None:
        if bank is None:
            if not isinstance(desk.bank, Bank):
                raise ValueError("template attacks need a simulated bank")
            bank = desk.bank
        self._bank = bank
        self._desk = desk
        self._gate_key = gate_key
        self._gate_pub = public_key_of(gate_key)
        self._hub = hub
        self._clock = clock
        self._nonces = nonces
        self._salts = salts

    def legit_call(self) -> RawCall:
        """Return the pinned legitimate call the attacks start from."""
        return _legit_call(self._desk.source)

    def run(self, kind: AttackKind) -> ConsoleLine:
        """Apply one template attack and publish its line.

        Args:
            kind: Which pinned attack to run.

        Returns:
            The published (numbered) attack line.
        """
        return self.apply(TEMPLATES[kind], None)

    def apply(self, plan: AttackPlan, trace: AttackerTrace | None) -> ConsoleLine:
        """Apply one plan to the simulated bank and publish its line.

        Args:
            plan: The attack to run.
            trace: The model call behind the plan, or None for a template.

        Returns:
            The published (numbered) attack line.
        """
        now, nonce = self._clock(), self._nonces()
        salt = None if self._salts is None else self._salts()
        outcome = self._desk.guarded(
            lambda _rail, verifier: apply_attack(
                plan,
                self.legit_call(),
                _INTENT,
                self._gate_key,
                self._bank,
                verifier,
                self._desk.source,
                now,
                nonce,
                salt=salt,
            )
        )
        origin = "template" if trace is None else "model"
        line = attack_line(plan, outcome, trace, origin, self._gate_pub)
        return self._hub.publish(line)


class DeployRunner:
    """Runs the pinned Nimbus steps against one simulated prod-eu.

    Args:
        gate_key: Raw Ed25519 private key the gate signs with.
        hub: Hub that receives the deploy lines.
        clock: Current unix time in seconds.
        nonces: Source of unique freshness nonces.
        salts: Source of 32-byte action salts, one per press; None lets the
            gate draw them.
    """

    def __init__(
        self,
        gate_key: bytes,
        hub: EventHub,
        clock: Callable[[], int],
        nonces: Callable[[], str],
        salts: Callable[[], bytes] | None = None,
    ) -> None:
        self._gate_key = gate_key
        self._gate_pub = public_key_of(gate_key)
        self._hub = hub
        self._clock = clock
        self._nonces = nonces
        self._salts = salts
        self._target = ProdTarget(self._gate_pub)
        self._lock = threading.Lock()

    def run(self, step: NimbusStep) -> ConsoleLine:
        """Run one Nimbus step and publish its line.

        Args:
            step: Which pinned step to run.

        Returns:
            The published (numbered) deploy line.
        """
        with self._lock:
            salt = None if self._salts is None else self._salts()
            outcome = run_step(
                step,
                self._gate_key,
                self._target,
                self._clock(),
                self._nonces(),
                salt,
            )
        return self._hub.publish(deploy_line(outcome, self._gate_pub))


class _ConsoleServer(uvicorn.Server):
    """Closes the event hub on exit, since open streams would block shutdown."""

    def __init__(self, config: uvicorn.Config, hub: EventHub) -> None:
        super().__init__(config)
        self._hub = hub

    def handle_exit(self, sig: int, frame: FrameType | None) -> None:
        self._hub.close()
        super().handle_exit(sig, frame)


def console_server(app: Any, host: str, port: int, hub: EventHub) -> _ConsoleServer:
    """Build the console's uvicorn server with a bounded graceful shutdown."""
    config = uvicorn.Config(
        app, host=host, port=port, timeout_graceful_shutdown=_GRACEFUL_SHUTDOWN_S
    )
    return _ConsoleServer(config, hub)


def _payee_book(path: Path) -> PayeeBook | None:
    try:
        return PayeeBook.from_json(json.loads(path.read_text()))
    except (OSError, ValueError, IntentError):
        return None


def _spark(
    env: os._Environ[str] | dict[str, str], book: PayeeBook
) -> tuple[IntentIntake | None, MetaClient | None]:
    # Without a key, drafting and the agent answer 503 and the holder page says so.
    try:
        key = api_key_from_env(env)
    except KeyError:
        return None, None
    meta = MetaClient(key)
    intake = IntentIntake(
        meta, book, lambda audio, words: transcribe(key, audio, words)
    )
    return intake, meta


def _sandbox(
    parser: argparse.ArgumentParser, key: str | None, names: tuple[str, ...]
) -> IncreaseRail:
    if key is None:
        parser.exit(2, f"bank rail unavailable: set {BANK_KEY_ENV}\n")
    try:
        rail = IncreaseRail.connect(sandbox_client(key))
    except (AuthenticationError, PermissionDeniedError):
        parser.exit(2, "bank rail unavailable: the sandbox refused the key\n")
    except IncreaseError:
        parser.exit(2, "bank rail unavailable: the sandbox is unreachable\n")
    if not rail.holds(names):
        parser.exit(2, "bank accounts missing: run mandate-bank-setup\n")
    return rail


def cli(argv: list[str] | None = None) -> None:
    """Console entry point for `mandate-console`.

    Serves the payment desk, the template attack route and the built console,
    and prints the pairing URL followed by the console URL. With
    ``--rail sandbox`` the desk pays through the Increase sandbox; the bank key
    leaves this process's environment either way, so nothing it spawns holds it.
    Template attacks always run on a simulated bank.
    """
    parser = argparse.ArgumentParser(
        prog="mandate-console", description="Serve the Mandate live console."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--source", default="checking-881")
    parser.add_argument(
        "--rail",
        choices=("simulated", "sandbox"),
        default="simulated",
        help="bank the desk pays through; sandbox needs INCREASE_SANDBOX_API_KEY",
    )
    parser.add_argument("--journal", type=Path, help="hook journal to follow")
    parser.add_argument("--record", type=Path, help="append every line as JSONL")
    parser.add_argument(
        "--live-attacker",
        action="store_true",
        help="let the console ask the open-weights attacker (spends model calls)",
    )
    parser.add_argument(
        "--voice",
        action="store_true",
        help="let the holder page transcribe spoken confirmations (spends Meta calls)",
    )
    parser.add_argument("--console-dir", type=Path, default=CONSOLE_DIST)
    parser.add_argument(
        "--payees",
        type=Path,
        default=DEMO_PAYEES,
        help="the holder's payee book, JSON of name to account and open invoices",
    )
    parser.add_argument(
        "--public-host",
        action="append",
        default=[],
        help=(
            "extra Host name the routes accept, e.g. an HTTPS proxy name; "
            "the console routes (/api/lines, /api/events, /api/forensic) show "
            "every payment's amount, payee, reference and debit account in "
            "clear to anyone who reaches that name: use a public host for "
            "demo data only"
        ),
    )
    args = parser.parse_args(argv)
    bank_key = take_bank_key(os.environ)
    index = args.console_dir / "index.html"
    if not index.is_file():
        parser.exit(2, f"console build missing: {index}\n")
    book = _payee_book(args.payees)
    if book is None:
        parser.exit(2, f"payee book unreadable: {args.payees}\n")
    simulated = Bank({args.source: _DEMO_BALANCE_CENTS, "acme-991": 0})
    rail: BankRail = (
        simulated
        if args.rail == "simulated"
        else _sandbox(parser, bank_key, (args.source, "acme-991"))
    )
    intake, agent = _spark(os.environ, book)
    hub = EventHub()
    if args.record is not None:
        hub.record(args.record)
    token = secrets.token_urlsafe(16)
    gate_key, gate_pub = generate_keypair()
    desk = PaymentDesk(
        source=args.source,
        bank=rail,
        verifier=Verifier(gate_pub),
        gate_key=gate_key,
        clock=_now,
        nonces=_nonce,
        publish=hub.publish,
    )
    runner = AttackRunner(
        desk, gate_key, hub, _now, counted_nonces("atk"), bank=simulated
    )
    deploys = DeployRunner(gate_key, hub, _now, counted_nonces("dep"))
    allowed = (*_LOCAL_HOSTS, *args.public_host)
    app = build_server(
        desk,
        token,
        allowed,
        hub=hub,
        attacks=runner,
        deploys=deploys,
        live=live_attacker(runner, os.environ, enabled=args.live_attacker),
        voice=transcriber_from_env(os.environ, enabled=args.voice),
        console_dir=args.console_dir,
        intake=intake,
        agent=agent,
    ).streamable_http_app()
    if args.journal is not None:
        # A daemon thread: the process ends with the server.
        JournalTail(args.journal, hub).start()
    base = f"http://{args.host}:{args.port}"
    print(f"Pair the holder device: {base}/app/#pair={token}", flush=True)
    print(f"Console: {base}/console/", flush=True)
    console_server(app, args.host, args.port, hub).run()
