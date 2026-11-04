"""Mandate console: desk, event hub, template attacks, Nimbus steps, console."""

import argparse
import itertools
import os
import secrets
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import FrameType
from typing import Any

import uvicorn

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import generate_keypair, public_key_of
from gate.policy import Intent
from gate.shim import RawCall
from swarm.attacker import AttackerTrace
from swarm.console_line import ConsoleLine, attack_line, deploy_line
from swarm.desk import PaymentDesk
from swarm.hub import EventHub
from swarm.journal_tail import JournalTail
from swarm.live_attack import live_attacker
from swarm.nimbus import NimbusStep, ProdTarget, run_step
from swarm.redteam import TEMPLATES, AttackKind, AttackPlan, apply_attack
from swarm.server import build_server

CONSOLE_DIST = Path(__file__).resolve().parent.parent / "console" / "dist"
_DEMO_BALANCE_CENTS = 10000000
_LOCAL_HOSTS = ("127.0.0.1", "localhost")
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
    """Applies the pinned template attacks to the desk's bank.

    Args:
        desk: Desk whose bank and verifier the attacks run against.
        gate_key: Raw Ed25519 private key the gate signs with.
        hub: Hub that receives the attack lines.
        clock: Current unix time in seconds.
        nonces: Source of unique freshness nonces.
    """

    def __init__(
        self,
        desk: PaymentDesk,
        gate_key: bytes,
        hub: EventHub,
        clock: Callable[[], int],
        nonces: Callable[[], str],
    ) -> None:
        self._desk = desk
        self._gate_key = gate_key
        self._gate_pub = public_key_of(gate_key)
        self._hub = hub
        self._clock = clock
        self._nonces = nonces

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
        """Apply one plan to the desk's bank and publish its line.

        Args:
            plan: The attack to run.
            trace: The model call behind the plan, or None for a template.

        Returns:
            The published (numbered) attack line.
        """
        now, nonce = self._clock(), self._nonces()
        outcome = self._desk.guarded(
            lambda bank, verifier: apply_attack(
                plan,
                self.legit_call(),
                _INTENT,
                self._gate_key,
                bank,
                verifier,
                self._desk.source,
                now,
                nonce,
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
    """

    def __init__(
        self,
        gate_key: bytes,
        hub: EventHub,
        clock: Callable[[], int],
        nonces: Callable[[], str],
    ) -> None:
        self._gate_key = gate_key
        self._gate_pub = public_key_of(gate_key)
        self._hub = hub
        self._clock = clock
        self._nonces = nonces
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
            outcome = run_step(
                step, self._gate_key, self._target, self._clock(), self._nonces()
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


def cli(argv: list[str] | None = None) -> None:
    """Console entry point for `mandate-console`.

    Serves the payment desk, the template attack route and the built console,
    and prints the pairing URL followed by the console URL.
    """
    parser = argparse.ArgumentParser(
        prog="mandate-console", description="Serve the Mandate live console."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--source", default="checking-881")
    parser.add_argument("--journal", type=Path, help="hook journal to follow")
    parser.add_argument("--record", type=Path, help="append every line as JSONL")
    parser.add_argument(
        "--live-attacker",
        action="store_true",
        help="let the console ask the open-weights attacker (spends model calls)",
    )
    parser.add_argument("--console-dir", type=Path, default=CONSOLE_DIST)
    parser.add_argument(
        "--public-host",
        action="append",
        default=[],
        help="extra Host name the routes accept, e.g. an HTTPS proxy name",
    )
    args = parser.parse_args(argv)
    index = args.console_dir / "index.html"
    if not index.is_file():
        parser.exit(2, f"console build missing: {index}\n")
    hub = EventHub()
    if args.record is not None:
        hub.record(args.record)
    token = secrets.token_urlsafe(16)
    gate_key, gate_pub = generate_keypair()
    desk = PaymentDesk(
        source=args.source,
        bank=Bank({args.source: _DEMO_BALANCE_CENTS, "acme-991": 0}),
        verifier=Verifier(gate_pub),
        gate_key=gate_key,
        clock=_now,
        nonces=_nonce,
        publish=hub.publish,
    )
    runner = AttackRunner(desk, gate_key, hub, _now, counted_nonces("atk"))
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
        console_dir=args.console_dir,
    ).streamable_http_app()
    if args.journal is not None:
        # A daemon thread: the process ends with the server.
        JournalTail(args.journal, hub).start()
    base = f"http://{args.host}:{args.port}"
    print(f"Pair the holder device: {base}/app/#pair={token}", flush=True)
    print(f"Console: {base}/console/", flush=True)
    console_server(app, args.host, args.port, hub).run()
