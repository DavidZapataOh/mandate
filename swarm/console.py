"""Mandate console: desk, event hub, template attacks, Nimbus steps, console."""

import argparse
import errno
import fcntl
import ipaddress
import itertools
import json
import logging
import os
import re
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
from typing import Any, NoReturn

import uvicorn
from increase import (
    AuthenticationError,
    Increase,
    IncreaseError,
    PermissionDeniedError,
)
from opentimestamps.calendar import RemoteCalendar

from bank.api import Bank
from bank.card import NO_AGENT_CARD, agent_card
from bank.credentials import (
    BANK_KEY_ENV,
    BANK_KEY_NAMES,
    HOLDER_KEY_ENV,
    WEBHOOK_SECRET_ENV,
    take_bank_key,
    take_holder_key,
    take_webhook_secret,
)
from bank.events import BankEvent, BankEvents
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
from gate.anchor_public import (
    AGGREGATORS,
    CALENDAR_TIMEOUT_S,
    HEADER_TIMEOUT_S,
    EsploraHeaders,
    PublicAnchors,
)
from gate.certs import generate_keypair, public_key_of
from gate.policy import Intent
from gate.shim import RawCall
from gate.state import StateStore, load_gate_key
from swarm.attacker import AttackerTrace
from swarm.card import (
    WEBHOOK_PATH,
    CardAuthorizer,
    card_webhook_app,
    card_webhook_server,
)
from swarm.console_line import ConsoleLine, attack_line, bank_line, deploy_line
from swarm.desk import PaymentDesk
from swarm.holders import MAX_HOLDERS, fingerprint
from swarm.hub import EventHub
from swarm.intake import IntentIntake
from swarm.intent import IntentError, PayeeBook
from swarm.journal_tail import JournalTail
from swarm.live_attack import live_attacker
from swarm.meta_client import MetaClient, api_key_from_env
from swarm.nimbus import NimbusStep, ProdTarget, run_step
from swarm.redteam import TEMPLATES, AttackKind, AttackPlan, apply_attack
from swarm.server import WEBAPP_DIR, build_server, split_listeners
from swarm.voice import transcribe, transcriber_from_env

CONSOLE_DIST = Path(__file__).resolve().parent.parent / "console" / "dist"
DEMO_PAYEES = Path(__file__).resolve().parent.parent / "demo" / "payees.json"
_DEMO_BALANCE_CENTS = 10000000
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
_MAX_PORT = 65535
_LOOPBACK_BINDS = ("127.0.0.1", "localhost", "::1")
_DNS_NAME = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]"
)
_GRACEFUL_SHUTDOWN_S = 2
RECONCILE_EVERY_S = 60
ANCHOR_EVERY_S = 600
BANK_EVENTS_EVERY_S = 5
# Best effort: a round that upgrades many proofs can outlast this; the store
# closes under it and its write fails closed, logged by type.
_ANCHOR_JOIN_S = CALENDAR_TIMEOUT_S * len(AGGREGATORS) + HEADER_TIMEOUT_S
_PRIVATE_DIR = 0o700
_NEEDS_STATE_DIR = "bank rail needs --state-dir: receipts must outlive the process\n"
_ANCHOR_NEEDS_STATE_DIR = (
    "public anchor needs --state-dir: proofs are upgraded hours later\n"
)
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
        local_port: int | None = None,
    ) -> None:
        super().__init__(config)
        self._hub = hub
        self._on_shutdown = on_shutdown
        self.local_port = local_port

    def run(self, sockets: list[socket.socket] | None = None) -> None:
        # One server, two sockets: the request's scope names the socket it
        # arrived on, which is what keeps local-only paths local.
        if sockets is None and self.local_port is not None:
            sockets = [
                self.config.bind_socket(),
                socket.create_server(("127.0.0.1", self.local_port)),
            ]
        super().run(sockets)

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
    *,
    trusted: tuple[str, ...] = (),
    local_port: int | None = None,
) -> _ConsoleServer:
    """Build the console's uvicorn server with a bounded graceful shutdown.

    Args:
        app: ASGI application to serve.
        host: Interface to bind.
        port: Port to bind.
        hub: Event hub closed on the exit signal.
        on_shutdown: Called once after every connection has closed.
        trusted: Addresses or networks whose X-Forwarded-Proto and
            X-Forwarded-For are believed; empty believes none.
        local_port: When given, a second socket on 127.0.0.1 at this port,
            served by the same app.

    Returns:
        The server.
    """
    # Passed explicitly: uvicorn's defaults trust loopback and whatever
    # FORWARDED_ALLOW_IPS names.
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        timeout_graceful_shutdown=_GRACEFUL_SHUTDOWN_S,
        proxy_headers=bool(trusted),
        forwarded_allow_ips=list(trusted),
    )
    return _ConsoleServer(config, hub, on_shutdown, local_port)


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
    parser: argparse.ArgumentParser,
    key: str,
    names: tuple[str, ...],
    two_step: bool = False,
    ach: bool = False,
) -> tuple[IncreaseRail, Increase]:
    try:
        client = sandbox_client(key)
        rail = IncreaseRail.connect(client, two_step=two_step, ach=ach)
    except (AuthenticationError, PermissionDeniedError):
        parser.exit(2, "bank rail unavailable: the sandbox refused the key\n")
    except IncreaseError:
        parser.exit(2, "bank rail unavailable: the sandbox is unreachable\n")
    if not rail.holds(names):
        parser.exit(2, "bank accounts missing: run mandate-bank-setup\n")
    if ach and not all(_pays_by_ach(rail, name) for name in names[1:]):
        parser.exit(2, "bank accounts missing: run mandate-bank-setup --ach\n")
    return rail, client


def _pays_by_ach(rail: IncreaseRail, name: str) -> bool:
    """Tell whether the rail knows where an ACH transfer to a payee goes."""
    try:
        rail.destination(name)
    except ValueError:
        return False
    return True


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


def _work_tree(path: Path) -> Path | None:
    """The first of a path and its parents that holds ``.git``, if any."""
    resolved = path.resolve()
    for folder in (resolved, *resolved.parents):
        if (folder / ".git").exists():
            return folder
    return None


def _state_dir_problem(path: Path) -> str | None:
    """Why a state directory cannot serve, or None; nothing is created."""
    tree = _work_tree(path)
    if tree is not None:
        return (
            f"state: directory is inside a git work tree ({tree}); "
            "keep it outside any repository"
        )
    if not path.exists() and not path.is_symlink():
        return None
    found = os.lstat(path)
    if not stat.S_ISDIR(found.st_mode) or found.st_uid != os.geteuid():
        return "state: directory must be this user's own directory"
    if found.st_mode & 0o077:
        return "state: directory must be private (chmod 700)"
    return None


def _hold(path: Path) -> int:
    """Lock a state directory for this process, creating it private.

    Two desks on one store would each trust their own memory of it, so a
    second process is refused instead of sharing the file.

    Returns:
        The descriptor holding the lock; closing it releases the directory.

    Raises:
        ValueError: If the directory is inside a git work tree, a link, not
            this user's, open to group or others, or held by another process.
    """
    problem = _state_dir_problem(path)
    if problem is not None:
        raise ValueError(problem)
    if not path.exists():
        path.mkdir(mode=_PRIVATE_DIR, parents=True)
        path.chmod(_PRIVATE_DIR)
    problem = _state_dir_problem(path)
    if problem is not None:
        raise ValueError(problem)
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


def anchor_every(
    anchors: PublicAnchors, every_s: float, stop: threading.Event
) -> threading.Thread:
    """Run an anchor round at once, then every ``every_s`` seconds until stopped.

    A round a third party kept from completing is logged with its reason, one
    that raised by its type only, and either is tried again at the next one;
    nothing waits on this thread but shutdown.

    Args:
        anchors: The store's public anchors.
        every_s: Seconds between rounds.
        stop: Set to end the loop.

    Returns:
        The started daemon thread.
    """

    def loop() -> None:
        anchor_round(anchors)
        while not stop.wait(every_s):
            anchor_round(anchors)

    thread = threading.Thread(target=loop, name="anchor", daemon=True)
    thread.start()
    return thread


def anchor_round(anchors: PublicAnchors) -> None:
    """Run one anchor round and log what kept it from completing.

    A reported `AnchorError` is logged at warning with its text, a fixed
    reason of the desk's; an exception is logged by its type only.

    Args:
        anchors: The store's public anchors.
    """
    try:
        done = anchors.round()
    except Exception as exc:
        # Only the type: a message could carry a third party's text.
        _log.error("anchor round failed (%s)", type(exc).__name__)
        return
    if done.error is not None:
        _log.warning("anchor round incomplete (%s)", done.error)


def bank_events_every(
    feed: BankEvents,
    hub: EventHub,
    every_s: float,
    stop: threading.Event,
    desk: PaymentDesk | None = None,
) -> threading.Thread:
    """Publish the bank's new events every ``every_s`` seconds until stopped.

    A round that fails is logged by its type and retried at the next one from
    the stored cursor.

    Args:
        feed: The bank's event feed.
        hub: Hub that receives the bank lines.
        every_s: Seconds between rounds; the first runs after one interval.
        stop: Set to end the loop.
        desk: Desk whose ACH payments the events update, if any.

    Returns:
        The started daemon thread.
    """

    def loop() -> None:
        while not stop.wait(every_s):
            bank_events_round(feed, hub, desk)

    thread = threading.Thread(target=loop, name="bank-events", daemon=True)
    thread.start()
    return thread


# The bank's event for any change to an ACH transfer; it names only the id.
_ACH_UPDATED = "ach_transfer.updated"


def bank_events_round(
    feed: BankEvents, hub: EventHub, desk: PaymentDesk | None = None
) -> None:
    """Publish one round of the bank's new events; a failure is logged by type.

    Events carry only ids, so each ACH transfer named by an update is read
    once after the round, and only when the desk tracks it. The reconcile
    round reads every tracked transfer anyway, so a read that fails here is
    only logged.

    Args:
        feed: The bank's event feed.
        hub: Hub that receives the bank lines.
        desk: Desk whose ACH payments the events update, if any.
    """
    updated: dict[str, None] = {}

    def publish(event: BankEvent) -> None:
        hub.publish(bank_line(event))
        if event.category == _ACH_UPDATED:
            updated[event.object_id] = None

    try:
        feed.poll(publish)
    except Exception as exc:
        # Only the type: a message could carry the bank's text.
        _log.error("bank events failed (%s)", type(exc).__name__)
    if desk is None:
        return
    for payment_id in updated:
        try:
            desk.track_ach(payment_id)
        except Exception as exc:
            # Only the type: a message could carry the bank's text.
            _log.error("ach lifecycle failed (%s)", type(exc).__name__)


def _port_free(listen: str) -> bool:
    host, _, port = listen.rpartition(":")
    with socket.socket() as probe:
        try:
            probe.bind((host, int(port)))
        except OSError:
            return False
    return True


def _zktls_ready(parser: argparse.ArgumentParser) -> str:
    """The verifier binary, once the notary could start; nothing is started."""
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
    return binary


def _zktls(
    parser: argparse.ArgumentParser, rail: BankRail, source: str
) -> tuple[Notary, BankProofSetup]:
    if not isinstance(rail, IncreaseRail):
        parser.exit(2, "zktls needs --rail sandbox\n")
    binary = _zktls_ready(parser)
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
    and prints one pairing URL per new holder device, the console URL, and the
    paired holders by id and fingerprint. ``--unpair`` retires a holder first. With
    ``--rail sandbox`` the desk pays through the Increase sandbox; the bank key
    leaves this process's environment either way, so nothing it spawns holds it.
    With ``--state-dir`` the gate key, registry, receipts and fences live in
    that directory, locked to this process and closed when the server stops;
    the sandbox rail requires it. The desk reconciles with its bank at start,
    and every ``RECONCILE_EVERY_S`` on the sandbox rail. ``--public-anchor``
    (needs ``--state-dir``) stamps the store's seals through public
    OpenTimestamps calendars at start and every ``ANCHOR_EVERY_S``. On the
    sandbox rail the console also shows the bank's own events every
    ``BANK_EVENTS_EVERY_S``. ``--two-step`` (needs ``--rail sandbox``) holds
    each quote at the bank until the certified confirm approves it. With
    ``--ach`` (needs ``--rail sandbox``) the desk pays by ACH transfer, and
    bank events of its transfers update their lifecycle. With
    ``--card-webhook-port`` (needs ``--rail sandbox``, not ``--two-step``)
    the bank's card authorizations are answered on a second app bound to
    127.0.0.1 alone, signed with ``INCREASE_SANDBOX_WEBHOOK_SECRET``; the
    secret leaves this process's environment either way. Template attacks
    always run on a simulated bank of their own and an in-memory verifier.
    ``--doctor`` runs the same checks, prints each credential only as present
    or absent, opens no store and exits.
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
        "--two-step",
        action="store_true",
        help=(
            "hold each quote at the bank as a transfer awaiting approval; "
            "the certified confirm approves it; needs --rail sandbox"
        ),
    )
    parser.add_argument(
        "--ach",
        action="store_true",
        help=(
            "pay each certified payment as an ACH transfer to the payee's "
            "account number; the bank settles or returns it later; "
            "needs --rail sandbox"
        ),
    )
    parser.add_argument(
        "--card-webhook-port",
        type=int,
        metavar="PORT",
        help=(
            "answer the bank's card authorizations on "
            f"127.0.0.1:PORT{WEBHOOK_PATH}; expose that port alone through an "
            "HTTPS tunnel; needs --rail sandbox and INCREASE_SANDBOX_WEBHOOK_SECRET"
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
    parser.add_argument(
        "--public-anchor",
        action="store_true",
        help=(
            "stamp every registry seal through public OpenTimestamps calendars "
            "and upgrade to Bitcoin; needs --state-dir"
        ),
    )
    parser.add_argument(
        "--holders",
        type=int,
        default=1,
        help="new holder devices to pair this start: one pairing URL each",
    )
    parser.add_argument(
        "--unpair",
        action="append",
        default=[],
        metavar="HOLDER_ID",
        help="stop trusting a paired holder before serving (needs --state-dir)",
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
    parser.add_argument("--webapp-dir", type=Path, default=WEBAPP_DIR)
    parser.add_argument(
        "--payees",
        type=Path,
        default=DEMO_PAYEES,
        help="the holder's payee book, JSON of name to account and open invoices",
    )
    parser.add_argument(
        "--trusted-proxy",
        action="append",
        default=[],
        metavar="ADDR",
        help=(
            "address or network of the HTTPS proxy in front of this console; "
            "forwarded headers from anyone else are ignored"
        ),
    )
    parser.add_argument(
        "--local-port",
        type=int,
        metavar="PORT",
        help=(
            "loopback port that alone serves /mcp and holder copies; "
            "needed whenever the console is published"
        ),
    )
    parser.add_argument(
        "--public-host",
        action="append",
        default=[],
        help=(
            "DNS name the HTTPS proxy publishes this console under; the routes "
            "accept it and the printed URLs use the first one; "
            "the console routes (/api/lines, /api/events, /api/forensic) show "
            "every payment's amount, payee, reference and debit account in "
            "clear to anyone who reaches that name: use a public host for "
            "demo data only"
        ),
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help=(
            "check what a start needs and exit: keys by presence only, "
            "no store opened, no money moved"
        ),
    )
    args = parser.parse_args(argv)
    _check_deploy_flags(parser, args)
    if args.two_step and args.rail != "sandbox":
        parser.exit(2, "--two-step needs --rail sandbox\n")
    if args.ach and args.rail != "sandbox":
        parser.exit(2, "--ach needs --rail sandbox\n")
    if args.ach and args.two_step:
        parser.exit(2, "--ach and --two-step are exclusive\n")
    if args.zktls:
        _zktls_flags(parser, args)
    present = frozenset(name for name in BANK_KEY_NAMES if os.environ.get(name))
    bank_key = take_bank_key(os.environ)
    # The holder proves in its own process; the value is never read here.
    take_holder_key(os.environ)
    # Taken whatever the flags, so nothing this process spawns holds it.
    webhook_secret = take_webhook_secret(os.environ)
    if args.doctor:
        _doctor(parser, args, bank_key, webhook_secret, present)
    hook_port: int | None = args.card_webhook_port
    if hook_port is not None:
        _card_flags(parser, args, webhook_secret)
    _console_builds(parser, args)
    book = _start_inputs(parser, args)
    _console_port_free(parser, args.host, args.port)
    _local_port_free(parser, args.local_port)
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
        client: Increase | None = None
        account_id: str | None = None
        if sandbox_key is None:
            with _state_errors(parser):
                rail = Bank(
                    {args.source: _DEMO_BALANCE_CENTS, "acme-991": 0}, state=state
                )
        else:
            rail, client = _sandbox(
                parser,
                sandbox_key,
                (args.source, "acme-991"),
                args.two_step,
                args.ach,
            )
            account_id = rail.account_id(args.source)
        notary, zktls = (
            _zktls(parser, rail, args.source) if args.zktls else (None, None)
        )
        if notary is not None:
            held.callback(notary.stop)
        hub = EventHub()
        if args.record is not None:
            hub.record(args.record)
        anchors = (
            PublicAnchors(
                state,
                public_key_of(gate_key),
                [RemoteCalendar(url) for url in AGGREGATORS],
                EsploraHeaders(),
                _now,
            )
            if args.public_anchor and state is not None
            else None
        )
        desk = _desk(parser, args.source, rail, gate_key, zktls, state, hub, anchors)
        for holder_id in args.unpair:
            if not desk.unpair_holder(holder_id):
                parser.error(f"not a paired holder: {holder_id}")
            print(f"Unpaired holder {holder_id}.", flush=True)
        feed = (
            BankEvents(client, state, desk.genesis, _now)
            if client is not None and state is not None
            else None
        )
        card = None
        # The flag checks above leave a sandbox client and a state store here.
        if (
            hook_port is not None
            and webhook_secret is not None
            and client is not None
            and state is not None
            and account_id is not None
        ):
            card = _card_webhook(
                parser, client, desk, state, webhook_secret, hook_port, account_id
            )
        _serve(parser, args, book, desk, gate_key, hub, held, anchors, feed, card)


def _console_builds(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    index = args.console_dir / "index.html"
    if not index.is_file():
        parser.exit(2, f"console build missing: {index}\n")
    webapp_index = args.webapp_dir / "index.html"
    if not webapp_index.is_file():
        parser.exit(2, f"holder web app missing: {webapp_index}\n")


def _start_inputs(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> PayeeBook:
    if not 0 <= args.holders <= MAX_HOLDERS:
        parser.error(f"--holders must be 0 to {MAX_HOLDERS}")
    if args.unpair and args.state_dir is None:
        parser.error("--unpair needs --state-dir: holders live in the state directory")
    if args.public_anchor and args.state_dir is None:
        parser.exit(2, _ANCHOR_NEEDS_STATE_DIR)
    book = _payee_book(args.payees)
    if book is None:
        parser.exit(2, f"payee book unreadable: {args.payees}\n")
    return book


def _doctor(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    bank_key: str | None,
    webhook_secret: str | None,
    present: frozenset[str],
) -> NoReturn:
    """Run a start's own checks in its order, print one line each, and exit.

    Opens no store: opening one creates the gate key and takes the
    directory's lock. On the sandbox rail it makes only the reads a start
    makes before serving; the agent card read and the notary are left to it.
    """
    hook_port: int | None = args.card_webhook_port
    if hook_port is not None:
        _card_flags(parser, args, webhook_secret)
    _console_builds(parser, args)
    print("console build: ok")
    print("holder web app: ok")
    _start_inputs(parser, args)
    _console_port_free(parser, args.host, args.port)
    _local_port_free(parser, args.local_port)
    for label, name, note in (
        ("bank key", BANK_KEY_ENV, ""),
        ("holder key", HOLDER_KEY_ENV, " (it belongs in the holder's own shell)"),
        ("webhook secret", WEBHOOK_SECRET_ENV, ""),
        (
            "sdk key",
            "INCREASE_API_KEY",
            " (never read here; keep it out of agent shells)",
        ),
        (
            "sdk webhook secret",
            "INCREASE_WEBHOOK_SECRET",
            " (never read here; removed at start)",
        ),
    ):
        state = f"present{note}" if name in present else "absent"
        print(f"{label} ({name}): {state}", flush=True)
    sandbox_key = (
        _sandbox_key(parser, bank_key, args.state_dir)
        if args.rail == "sandbox"
        else None
    )
    if args.state_dir is None:
        print("state dir: not set (state lives in memory)")
    else:
        problem = _state_dir_problem(args.state_dir)
        if problem is not None:
            parser.exit(2, f"{problem}\n")
        kept = (
            "private" if args.state_dir.exists() else "created private at first start"
        )
        print(f"state dir: {args.state_dir} ({kept})")
    if sandbox_key is None:
        print("bank rail: simulated")
    else:
        names = (args.source, "acme-991")
        _sandbox(parser, sandbox_key, names, args.two_step, args.ach)
        print(f"bank rail: sandbox, accounts {args.source} and acme-991 open")
    if args.two_step:
        print("two-step: each quote held at the bank until the certified confirm")
    if args.ach:
        print("ach: acme-991 has an active account number")
    if args.zktls:
        _zktls_ready(parser)
        print(
            f"zktls: verifier found, notary {NOTARY_LISTEN} free "
            "(the notary starts at start)"
        )
    if hook_port is not None:
        if not _port_free(f"127.0.0.1:{hook_port}"):
            parser.exit(
                2, f"card webhook unavailable: 127.0.0.1:{hook_port} is in use\n"
            )
        print(
            f"card webhook: 127.0.0.1:{hook_port} free "
            "(the agent card is read at start)"
        )
    if args.local_port is not None:
        print(f"local port: 127.0.0.1:{args.local_port} free")
    print("doctor: ready", flush=True)
    parser.exit(0)


def _check_deploy_flags(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    trusted = []
    for value in args.trusted_proxy:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network = None
        # A /0 trusts everyone, like "*".
        if network is None or network.prefixlen == 0:
            parser.exit(
                2, f"--trusted-proxy must be an IP address or network: {value}\n"
            )
        single = network.prefixlen == network.max_prefixlen
        trusted.append(str(network.network_address if single else network))
    # Normalised: uvicorn parses networks strictly, and would silently never
    # match one written with host bits (10.1.2.3/8).
    args.trusted_proxy = trusted
    for value in args.public_host:
        if _DNS_NAME.fullmatch(value.lower()) is None:
            parser.exit(
                2,
                f"--public-host must be a DNS name such as desk.example.com: {value}\n",
            )
    args.public_host = [value.lower() for value in args.public_host]
    if args.local_port is not None and not 1 <= args.local_port <= _MAX_PORT:
        parser.exit(2, f"--local-port must be 1 to {_MAX_PORT}\n")
    if args.local_port is not None and args.local_port == args.port:
        parser.exit(2, "--local-port must differ from --port\n")
    public = bool(args.public_host) or args.host not in _LOOPBACK_BINDS
    if public and args.local_port is None:
        parser.exit(
            2,
            "a public listener needs --local-port: /mcp and holder copies stay "
            "on a loopback port the public never reaches\n",
        )
    if args.public_host and not args.trusted_proxy:
        parser.exit(
            2,
            "--public-host needs --trusted-proxy: the address of the HTTPS "
            "proxy in front of the console\n",
        )


def _zktls_flags(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.rail != "sandbox":
        parser.exit(2, "zktls needs --rail sandbox\n")
    notary_port = int(NOTARY_LISTEN.rpartition(":")[2])
    for flag, port in (
        ("--local-port", args.local_port),
        ("--card-webhook-port", args.card_webhook_port),
    ):
        if port == notary_port:
            parser.exit(2, f"{flag} must differ from the notary's port ({port})\n")


def _console_port_free(parser: argparse.ArgumentParser, host: str, port: int) -> None:
    # The main socket binds inside the server's run, after the URLs are
    # printed and the store is open; a busy port is named here instead.
    try:
        family, kind, _, _, address = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )[0]
        with socket.socket(family, kind) as probe:
            # As uvicorn binds: a closed connection's TIME_WAIT is no tenant.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(address)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            parser.exit(2, f"port unavailable: {host}:{port} is in use\n")
        parser.exit(2, f"port unavailable: {host}:{port}: {exc.strerror}\n")


def _local_port_free(parser: argparse.ArgumentParser, port: int | None) -> None:
    # The second socket binds inside the server's run, after the URLs are
    # printed and the store is open; a busy port is named here instead.
    if port is not None and not _port_free(f"127.0.0.1:{port}"):
        parser.exit(2, f"local port unavailable: 127.0.0.1:{port} is in use\n")


def _card_flags(
    parser: argparse.ArgumentParser, args: argparse.Namespace, secret: str | None
) -> None:
    if args.rail != "sandbox":
        parser.exit(2, "--card-webhook-port needs --rail sandbox\n")
    # A two-step desk refuses every card spend ("card: two-step desk"): the
    # bank would ask and always hear no, so the start refuses instead.
    if args.two_step:
        parser.exit(2, "--card-webhook-port cannot be combined with --two-step\n")
    if secret is None:
        parser.exit(2, f"card webhook unavailable: set {WEBHOOK_SECRET_ENV}\n")
    if args.card_webhook_port == args.port:
        parser.exit(2, "--card-webhook-port must differ from --port\n")
    if args.card_webhook_port == args.local_port:
        parser.exit(2, "--card-webhook-port must differ from --local-port\n")


def _card_webhook(
    parser: argparse.ArgumentParser,
    client: Increase,
    desk: PaymentDesk,
    state: StateStore,
    secret: str,
    port: int,
    account_id: str,
) -> uvicorn.Server:
    try:
        card_id = agent_card(client, account_id)
    except (AuthenticationError, PermissionDeniedError):
        parser.exit(2, "bank rail unavailable: the sandbox refused the key\n")
    except IncreaseError:
        parser.exit(2, "bank rail unavailable: the sandbox is unreachable\n")
    if card_id is None:
        parser.exit(2, NO_AGENT_CARD)
    # A refused bind would end the server's thread unseen, so it is named here.
    if not _port_free(f"127.0.0.1:{port}"):
        parser.exit(2, f"card webhook unavailable: 127.0.0.1:{port} is in use\n")
    authorizer = CardAuthorizer(client, desk, card_id, account_id, state)
    return card_webhook_server(card_webhook_app(client, authorizer, secret), port)


def _desk(
    parser: argparse.ArgumentParser,
    source: str,
    rail: BankRail,
    gate_key: bytes,
    zktls: BankProofSetup | None,
    state: StateStore | None,
    hub: EventHub,
    anchors: PublicAnchors | None,
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
            anchors=anchors,
        )


def _serve(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    book: PayeeBook,
    desk: PaymentDesk,
    gate_key: bytes,
    hub: EventHub,
    held: ExitStack,
    anchors: PublicAnchors | None,
    feed: BankEvents | None,
    card: uvicorn.Server | None = None,
) -> None:
    intake, agent = _spark(os.environ, book)
    tokens = tuple(secrets.token_urlsafe(16) for _ in range(args.holders))
    # Attacks move money on a bank of their own, never the desk's store.
    attack_bank = Bank({args.source: _DEMO_BALANCE_CENTS, "acme-991": 0})
    runner = AttackRunner(
        desk, gate_key, hub, _now, counted_nonces("atk"), bank=attack_bank
    )
    deploys = DeployRunner(gate_key, hub, _now, counted_nonces("dep"))
    allowed = (*_LOCAL_HOSTS, *args.public_host)
    served = build_server(
        desk,
        tokens,
        allowed,
        hub=hub,
        attacks=runner,
        deploys=deploys,
        live=live_attacker(runner, os.environ, enabled=args.live_attacker),
        voice=transcriber_from_env(os.environ, enabled=args.voice),
        console_dir=args.console_dir,
        intake=intake,
        agent=agent,
        anchors=anchors,
        local_port=args.local_port,
        webapp_dir=args.webapp_dir,
        on_paired=_announce,
    ).streamable_http_app()
    app = (
        served if args.local_port is None else split_listeners(served, args.local_port)
    )
    # A round that fails leaves its reason in the view; the console serves.
    reconcile_round(desk)
    if desk.bank.rail == SANDBOX:
        stop = threading.Event()
        loop = reconcile_every(desk, RECONCILE_EVERY_S, stop)
        # Unwound first: a round still asking the bank ends before the store
        # closes.
        held.callback(_end_loop, stop, loop)
    if feed is not None:
        stop_feed = threading.Event()
        feeding = bank_events_every(feed, hub, BANK_EVENTS_EVERY_S, stop_feed, desk)
        # Unwound before the store closes, like the reconcile loop.
        held.callback(_end_loop, stop_feed, feeding)
    if anchors is not None:
        stop_anchoring = threading.Event()
        anchoring = anchor_every(anchors, ANCHOR_EVERY_S, stop_anchoring)
        # Unwound before the store closes, like the reconcile loop.
        held.callback(_end_loop, stop_anchoring, anchoring, _ANCHOR_JOIN_S)
    if card is not None:
        answering = threading.Thread(target=card.run, name="card-webhook", daemon=True)
        answering.start()
        # Unwound before the store closes: an answer in flight ends first.
        held.callback(_end_card_webhook, card, answering)
    if args.journal is not None:
        # A daemon thread: the process ends with the server.
        JournalTail(args.journal, hub).start()
    # The public name is configuration, never read from a request.
    base = (
        f"https://{args.public_host[0]}"
        if args.public_host
        else f"http://{args.host}:{args.port}"
    )
    for token in tokens:
        print(f"Pair the holder device: {base}/app/#pair={token}", flush=True)
    print(f"Console: {base}/console/", flush=True)
    if args.local_port is not None:
        mcp = f"http://127.0.0.1:{args.local_port}/mcp"
        print(f"MCP for agents on this machine: {mcp}", flush=True)
    if card is not None:
        hook = f"http://127.0.0.1:{card.config.port}{WEBHOOK_PATH}"
        print(f"Card authorizations: {hook}", flush=True)
    for holder_id, key in desk.paired_holders():
        print(f"Holder {holder_id}: device {fingerprint(key)}", flush=True)
    console_server(
        app,
        args.host,
        args.port,
        hub,
        held.close,
        trusted=tuple(args.trusted_proxy),
        local_port=args.local_port,
    ).run()


def _announce(holder_id: str, key: bytes) -> None:
    print(f"Holder {holder_id}: device {fingerprint(key)}", flush=True)


def _end_loop(
    stop: threading.Event, loop: threading.Thread, wait_s: float = RECONCILE_EVERY_S
) -> None:
    stop.set()
    loop.join(wait_s)


def _end_card_webhook(server: uvicorn.Server, thread: threading.Thread) -> None:
    server.should_exit = True
    thread.join(RECONCILE_EVERY_S)
