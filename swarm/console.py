"""Mandate console: desk, event hub, template attacks, Nimbus steps, console."""

import argparse
import fcntl
import itertools
import json
import logging
import os
import secrets
import socket
import sqlite3
import stat
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import FrameType
from typing import Any

import uvicorn
from increase import AuthenticationError, IncreaseError, PermissionDeniedError

from bank.api import Bank
from bank.credentials import BANK_KEY_ENV, take_bank_key, take_holder_key
from bank.increase import IncreaseRail, sandbox_client
from bank.rail import SANDBOX, BankRail
from bank.verifier import Verifier
from evidence.notary import (
    NOTARY_LISTEN,
    Notary,
    NotaryError,
    new_notary_key,
    start_notary,
)
from evidence.zktls import ZKTLS_BIN_ENV, BankProofSetup, find_verifier
from gate.certs import generate_keypair, public_key_of
from gate.policy import Intent
from gate.shim import RawCall
from gate.state import StateStore, load_gate_key
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
RECONCILE_EVERY_S = 60
_PRIVATE_DIR = 0o700
_NEEDS_STATE_DIR = "bank rail needs --state-dir: receipts must outlive the process\n"
_log = logging.getLogger(__name__)
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
    reach a real rail or the desk's durable fences: they run against a
    simulated bank and an in-memory verifier of their own, under the desk's
    lock.

    Args:
        desk: Desk whose lock and debit account the attacks use.
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
        self._verifier = Verifier(self._gate_pub)
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
            lambda _rail, _verifier: apply_attack(
                plan,
                self.legit_call(),
                _INTENT,
                self._gate_key,
                self._bank,
                self._verifier,
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

    def __init__(
        self,
        config: uvicorn.Config,
        hub: EventHub,
        on_shutdown: Callable[[], object] | None = None,
    ) -> None:
        super().__init__(config)
        self._hub = hub
        self._on_shutdown = on_shutdown

    def handle_exit(self, sig: int, frame: FrameType | None) -> None:
        self._hub.close()
        super().handle_exit(sig, frame)

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        await super().shutdown(sockets)
        # uvicorn re-raises the stop signal once `run` returns, so code after
        # `run` never runs on a signal; this is the last point that does.
        if self._on_shutdown is not None:
            self._on_shutdown()


def console_server(
    app: Any,
    host: str,
    port: int,
    hub: EventHub,
    on_shutdown: Callable[[], object] | None = None,
) -> _ConsoleServer:
    """Build the console's uvicorn server with a bounded graceful shutdown.

    Args:
        app: ASGI application to serve.
        host: Interface to bind.
        port: Port to bind.
        hub: Event hub closed on the exit signal.
        on_shutdown: Called once after every connection has closed.

    Returns:
        The server.
    """
    config = uvicorn.Config(
        app, host=host, port=port, timeout_graceful_shutdown=_GRACEFUL_SHUTDOWN_S
    )
    return _ConsoleServer(config, hub, on_shutdown)


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


def _sandbox_key(
    parser: argparse.ArgumentParser, key: str | None, state_dir: Path | None
) -> str:
    if key is None:
        parser.exit(2, f"bank rail unavailable: set {BANK_KEY_ENV}\n")
    if state_dir is None:
        parser.exit(2, _NEEDS_STATE_DIR)
    return key


def _sandbox(
    parser: argparse.ArgumentParser, key: str, names: tuple[str, ...]
) -> IncreaseRail:
    try:
        rail = IncreaseRail.connect(sandbox_client(key))
    except (AuthenticationError, PermissionDeniedError):
        parser.exit(2, "bank rail unavailable: the sandbox refused the key\n")
    except IncreaseError:
        parser.exit(2, "bank rail unavailable: the sandbox is unreachable\n")
    if not rail.holds(names):
        parser.exit(2, "bank accounts missing: run mandate-bank-setup\n")
    return rail


@contextmanager
def _state_errors(parser: argparse.ArgumentParser) -> Iterator[None]:
    """Turn a store that cannot serve into exit 2 with its reason."""
    try:
        yield
    except ValueError as exc:
        if not str(exc).startswith("state: "):
            raise
        parser.exit(2, f"{exc}\n")
    except sqlite3.Error as exc:
        parser.exit(2, f"state: {exc}\n")


def _hold(path: Path) -> int:
    """Lock a state directory for this process, creating it private.

    Two desks on one store would each trust their own memory of it, so a
    second process is refused instead of sharing the file.

    Returns:
        The descriptor holding the lock; closing it releases the directory.

    Raises:
        ValueError: If the directory is a link, not this user's, open to
            group or others, or held by another process.
    """
    if not path.exists():
        path.mkdir(mode=_PRIVATE_DIR, parents=True)
        path.chmod(_PRIVATE_DIR)
    found = os.lstat(path)
    if not stat.S_ISDIR(found.st_mode) or found.st_uid != os.geteuid():
        raise ValueError("state: directory must be this user's own directory")
    if found.st_mode & 0o077:
        raise ValueError("state: directory must be private (chmod 700)")
    held = os.open(path / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(held)
        raise ValueError("state: directory in use") from None
    return held


def _open_state(
    parser: argparse.ArgumentParser, path: Path, held: ExitStack
) -> tuple[StateStore, bytes]:
    with _state_errors(parser):
        try:
            held.callback(os.close, _hold(path))
            gate_key = load_gate_key(path / "gate.key")
        except OSError as exc:
            parser.exit(2, f"state: {path}: {exc.strerror}\n")
        store = StateStore(path / "state.db")
    # Closed before the lock is released: the last connection folds the
    # write-ahead log into state.db, so that one file holds every commit.
    held.callback(store.close)
    return store, gate_key


def reconcile_every(
    desk: PaymentDesk, every_s: float, stop: threading.Event
) -> threading.Thread:
    """Reconcile the desk with its bank every ``every_s`` seconds until stopped.

    A round that fails for any reason is logged by its type and tried again
    at the next one; the desk keeps a view naming the failure and its time.

    Args:
        desk: Desk to reconcile.
        every_s: Seconds between rounds; the first runs after one interval.
        stop: Set to end the loop.

    Returns:
        The started daemon thread.
    """

    def loop() -> None:
        while not stop.wait(every_s):
            reconcile_round(desk)

    thread = threading.Thread(target=loop, name="reconcile", daemon=True)
    thread.start()
    return thread


def reconcile_round(desk: PaymentDesk) -> None:
    """Run one reconciliation round; a failure is logged by its type only.

    Args:
        desk: Desk to reconcile.
    """
    try:
        desk.reconcile()
    except Exception as exc:
        # Only the type: a message could carry bank or consent fields.
        _log.error("reconcile failed (%s)", type(exc).__name__)


def _port_free(listen: str) -> bool:
    host, _, port = listen.rpartition(":")
    with socket.socket() as probe:
        try:
            probe.bind((host, int(port)))
        except OSError:
            return False
    return True


def _zktls(
    parser: argparse.ArgumentParser, rail: BankRail, source: str
) -> tuple[Notary, BankProofSetup]:
    if not isinstance(rail, IncreaseRail):
        parser.exit(2, "zktls needs --rail sandbox\n")
    binary = find_verifier(os.environ)
    if binary is None:
        parser.exit(
            2, f"zktls unavailable: set {ZKTLS_BIN_ENV} to a built mandate-zktls\n"
        )
    # The child cannot report a refused bind, so a busy port is named here.
    if not _port_free(NOTARY_LISTEN):
        parser.exit(
            2, f"zktls unavailable: notary: {NOTARY_LISTEN} is already in use\n"
        )
    try:
        notary = start_notary(binary, new_notary_key(), NOTARY_LISTEN)
    except NotaryError as exc:
        parser.exit(2, f"zktls unavailable: {exc}\n")
    setup = BankProofSetup(
        binary, notary.address, notary.public_key, {source: rail.account_id(source)}
    )
    return notary, setup


def cli(argv: list[str] | None = None) -> None:
    """Console entry point for `mandate-console`.

    Serves the payment desk, the template attack route and the built console,
    and prints the pairing URL followed by the console URL. With
    ``--rail sandbox`` the desk pays through the Increase sandbox; the bank key
    leaves this process's environment either way, so nothing it spawns holds it.
    With ``--state-dir`` the gate key, registry, receipts and fences live in
    that directory, locked to this process and closed when the server stops;
    the sandbox rail requires it. The desk reconciles with its bank at start,
    and every ``RECONCILE_EVERY_S`` on the sandbox rail. Template attacks
    always run on a simulated bank of their own and an in-memory verifier.
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
    parser.add_argument(
        "--zktls",
        action="store_true",
        help=(
            "start Mandate's notary so the holder can prove the sandbox balance; "
            "needs --rail sandbox and MANDATE_ZKTLS_BIN"
        ),
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        help=(
            "directory that keeps the gate key, the registry, receipts and "
            "fences across restarts (keep it outside any repository, e.g. "
            "~/.mandate-demo); needed by --rail sandbox; default: in memory"
        ),
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
    # The holder proves in its own process; the value is never read here.
    take_holder_key(os.environ)
    index = args.console_dir / "index.html"
    if not index.is_file():
        parser.exit(2, f"console build missing: {index}\n")
    book = _payee_book(args.payees)
    if book is None:
        parser.exit(2, f"payee book unreadable: {args.payees}\n")
    sandbox_key = (
        _sandbox_key(parser, bank_key, args.state_dir)
        if args.rail == "sandbox"
        else None
    )
    with ExitStack() as held:
        state, gate_key = (
            (None, generate_keypair()[0])
            if args.state_dir is None
            else _open_state(parser, args.state_dir, held)
        )
        rail: BankRail
        if sandbox_key is None:
            with _state_errors(parser):
                rail = Bank(
                    {args.source: _DEMO_BALANCE_CENTS, "acme-991": 0}, state=state
                )
        else:
            rail = _sandbox(parser, sandbox_key, (args.source, "acme-991"))
        notary, zktls = (
            _zktls(parser, rail, args.source) if args.zktls else (None, None)
        )
        if notary is not None:
            held.callback(notary.stop)
        hub = EventHub()
        if args.record is not None:
            hub.record(args.record)
        desk = _desk(parser, args.source, rail, gate_key, zktls, state, hub)
        _serve(parser, args, book, desk, gate_key, hub, held)


def _desk(
    parser: argparse.ArgumentParser,
    source: str,
    rail: BankRail,
    gate_key: bytes,
    zktls: BankProofSetup | None,
    state: StateStore | None,
    hub: EventHub,
) -> PaymentDesk:
    # Loading the registry checks every stored seal; a store that fails it
    # stops the start like any other store error.
    with _state_errors(parser):
        return PaymentDesk(
            source=source,
            bank=rail,
            verifier=Verifier(public_key_of(gate_key), state=state),
            gate_key=gate_key,
            clock=_now,
            nonces=_nonce,
            publish=hub.publish,
            zktls=zktls,
            state=state,
        )


def _serve(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    book: PayeeBook,
    desk: PaymentDesk,
    gate_key: bytes,
    hub: EventHub,
    held: ExitStack,
) -> None:
    intake, agent = _spark(os.environ, book)
    token = secrets.token_urlsafe(16)
    # Attacks move money on a bank of their own, never the desk's store.
    attack_bank = Bank({args.source: _DEMO_BALANCE_CENTS, "acme-991": 0})
    runner = AttackRunner(
        desk, gate_key, hub, _now, counted_nonces("atk"), bank=attack_bank
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
    # A round that fails leaves its reason in the view; the console serves.
    reconcile_round(desk)
    if desk.bank.rail == SANDBOX:
        stop = threading.Event()
        loop = reconcile_every(desk, RECONCILE_EVERY_S, stop)
        # Unwound first: a round still asking the bank ends before the store
        # closes.
        held.callback(_end_loop, stop, loop)
    if args.journal is not None:
        # A daemon thread: the process ends with the server.
        JournalTail(args.journal, hub).start()
    base = f"http://{args.host}:{args.port}"
    print(f"Pair the holder device: {base}/app/#pair={token}", flush=True)
    print(f"Console: {base}/console/", flush=True)
    console_server(app, args.host, args.port, hub, held.close).run()


def _end_loop(stop: threading.Event, loop: threading.Thread) -> None:
    stop.set()
    loop.join(RECONCILE_EVERY_S)
