"""Payment desk: holder intent, quote, holder approval, gated confirm, receipt."""

import base64
import dataclasses
import json
import logging
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar, overload

from bank.api import Payment, PaymentRequest, RailError
from bank.rail import SANDBOX, BankRail, idempotency_key
from bank.reconcile import (
    CANCELED,
    BankTransfer,
    Reconciliation,
    TransferLedger,
    compare,
)
from bank.verifier import Verifier, action_commitment
from evidence.cooperative import sign_state
from evidence.seams import opaque_cooperative_ref, opaque_intent_ref
from evidence.zktls import (
    BANK_HOST,
    PROOF_TTL_S,
    BalanceProof,
    BankProofSetup,
    ZktlsError,
)
from gate.cava import ACTION_SALT_LEN, CavaAction, Freshness, canonical_bytes
from gate.certs import generate_keypair, public_key_of
from gate.consent import (
    Consent,
    ConsentLedger,
    HolderApproval,
    consent_bytes,
    verify_signature,
    with_approval,
)
from gate.events import DecisionEvent
from gate.policy import Intent, Policy, Rule
from gate.registry import Anchor, InclusionProof, LogEntry, Registry
from gate.shim import Mode, RawCall, canonize
from gate.state import StateStore, iso_utc
from mandate.client import RunRequest, RunResult, run_governed, to_proposed
from swarm.console_line import ConsoleLine, desk_line, forensic_of, pay_summary
from swarm.intent import IntentError, confirmed_intent, intent_hash
from swarm.meta_client import reasoning_commitment
from swarm.receipt import proof_receipt, seal_view

DESK_POLICY = Policy(
    "desk",
    1,
    (
        Rule(
            "pay-with-consent", "mcp:bank.pay", "transfer", "*", True, None, False, True
        ),
    ),
)
_log = logging.getLogger(__name__)
_KEY_LEN = 32
_REVOCATION_BITS = 1024
_STATEMENT_TTL_S = 300
# Rail outcomes after which the bank may hold a transfer under the key: the
# bound intent pays nothing more until a lookup by the idempotency key settles it.
_DIFFERS = "bank: transfer differs"
_UNSETTLED = ("bank: outcome unknown", "bank: not complete", _DIFFERS)
# A lookup that finds nothing releases an intent only this long after the
# attempt: a transfer whose answer was lost may still be committing.
SETTLE_WINDOW_S = 60
_NOT_YET = "bank: no transfer yet"
_OUTCOME_UNKNOWN = "bank: outcome unknown"
_NOT_COMPLETE = "bank: not complete"
_RECONCILED = "ok: reconciled at the bank"
_NOT_PAID = "bank: no transfer under this certificate"
_BYTE_FIELDS = ("signature", "consent_key", "key_signature")
_T = TypeVar("_T")


@dataclass
class _Quote:
    number: int
    consent: Consent
    status: str = "quoted"
    result: dict[str, Any] | None = None
    intent_id: str | None = None


@dataclass(frozen=True)
class _Unsettled:
    quote_id: str
    request: PaymentRequest
    action_hash: str
    key: str
    reason: str
    since: int


@dataclass
class _Intent:
    intent: Intent
    hash: str
    funds_ref: str
    intent_ref: str
    payment_id: str | None = None
    unsettled: _Unsettled | None = None
    funds: dict[str, Any] | None = None


# The debit account stays out of the certificate: the salted action hash
# binds it, and the bank verifier checks it inside the exact action.
PAY_SCOPE = "mcp:bank.pay:transfer"


class PaymentDesk:
    """Holds quotes until the holder signs, then pays once through the gate.

    The holder may first sign an intent on their own device. The desk keeps
    only the reference of the bank statement it signs for that intent. A quote
    naming an intent is checked against it at the gate; a quote naming none is
    checked against the holder's consent only.

    Args:
        source: Account every quote debits.
        bank: Rail the confirmed payments execute against.
        verifier: Certificate verifier bound to the gate's public key.
        gate_key: Raw Ed25519 private key the gate signs certificates with.
        clock: Current unix time in seconds.
        nonces: Source of unique nonces for consents and certificates.
        quote_ttl_s: Seconds a quote stays approvable.
        publish: Receives one console line per desk step, under the desk lock,
            so line order is the desk's order.
        action_salts: Source of 32-byte action salts, one per confirm; None
            draws them from the operating system.
        salts: Source of 16-byte SD-JWT Disclosure salts for proof receipts;
            None draws them from the operating system.
        bank_key: Raw Ed25519 private key the simulated bank signs funds
            statements with; None generates a fresh one.
        require_intent: When True, a quote naming no intent is denied at
            confirm before the gate runs; always on for a sandbox rail.
        zktls: Verifier, notary and accounts for zkTLS balance proofs of an
            intent's funds; None leaves the cooperative statement as the only
            funds evidence.
        state: Durable store the desk loads its holder, counters, intents,
            receipts, results, final quotes and registry from and writes
            through to; None keeps everything in memory. Open quotes are not
            kept. One process per store.

    Raises:
        ValueError: If ``zktls`` is given for a rail other than the sandbox.
    """

    def __init__(
        self,
        source: str,
        bank: BankRail,
        verifier: Verifier,
        gate_key: bytes,
        clock: Callable[[], int],
        nonces: Callable[[], str],
        quote_ttl_s: int = 600,
        publish: Callable[[ConsoleLine], object] | None = None,
        action_salts: Callable[[], bytes] | None = None,
        salts: Callable[[], bytes] | None = None,
        *,
        bank_key: bytes | None = None,
        require_intent: bool = False,
        zktls: BankProofSetup | None = None,
        state: StateStore | None = None,
    ) -> None:
        # A proof of an Increase balance says nothing about any other bank.
        if zktls is not None and bank.rail != SANDBOX:
            raise ValueError("zktls needs the sandbox rail")
        self.bank = bank
        self._zktls = zktls
        self._source = source
        self._verifier = verifier
        self._gate_key = gate_key
        self._clock = clock
        self._nonces = nonces
        self._ttl = quote_ttl_s
        self._publish = publish
        self._action_salts = action_salts or (lambda: os.urandom(ACTION_SALT_LEN))
        self._salts = salts or (lambda: os.urandom(16))
        self._gate_pub = public_key_of(gate_key)
        self._bank_key = generate_keypair()[0] if bank_key is None else bank_key
        self._bank_pub = public_key_of(self._bank_key)
        self._require_intent = require_intent or bank.rail == SANDBOX
        # Seals use the gate key: the "anchor/v1:" prefix cannot collide with
        # a JWS signing input, so one published key verifies both.
        self._state = state
        self.registry = Registry(keypair=(gate_key, self._gate_pub), state=state)
        self._ledger = ConsentLedger(state=state)
        self._holders: tuple[bytes, ...] = ()
        self._quotes: dict[str, _Quote] = {}
        self._receipts: dict[str, dict[str, Any]] = {}
        # Holder copies: every Disclosure, the action salt included, so they
        # leave the desk only through `proof_receipt`.
        self._proofs: dict[str, dict[str, Any]] = {}
        self._seq = 0
        self._intents: dict[str, _Intent] = {}
        self._intent_hashes: set[str] = set()
        # Final results of quotes from an earlier process, by quote id.
        self._closed: dict[str, dict[str, Any]] = {}
        # Transfers made before this registry existed are not its to explain.
        self._genesis = iso_utc(clock())
        self._reconciliation: dict[str, Any] | None = None
        # HTTP routes and the MCP session run on different threads.
        self._lock = threading.Lock()
        if state is not None:
            self._load(state)

    def _load(self, state: StateStore) -> None:
        genesis = state.get("genesis")
        if genesis is None:
            state.put("genesis", self._genesis)
        else:
            self._genesis = genesis
        reconciliation = state.get("reconciliation")
        if reconciliation is not None:
            self._reconciliation = json.loads(reconciliation)
        holders = json.loads(state.get("holders") or "[]")
        self._holders = tuple(base64.b64decode(k) for k in holders)
        self._seq = int(state.get("quote_seq") or "0")
        for intent_id, value in state.records("intent"):
            stored = _intent_from(json.loads(value))
            self._intents[intent_id] = stored
            self._intent_hashes.add(stored.hash)
        self._receipts = {k: json.loads(v) for k, v in state.records("result")}
        self._proofs = {k: json.loads(v) for k, v in state.records("receipt")}
        self._closed = {k: json.loads(v) for k, v in state.records("quote")}
        for quote_id, value in state.records("pending"):
            if quote_id not in self._closed:
                self._crashed(quote_id, json.loads(value))

    def _crashed(self, quote_id: str, journal: dict[str, Any]) -> None:
        """Adopt a confirm the process died in after the certificate existed.

        The bank may hold the transfer, so the quote reads as an unknown
        outcome and its intent pays nothing more until a lookup settles it.
        """
        self._closed[quote_id] = _outcome_unknown(quote_id)
        found = self._intents.get(journal["intent_id"] or "")
        if found is None or found.payment_id is not None or found.unsettled:
            return
        action = _action_from(journal["action"])
        found.unsettled = _Unsettled(
            quote_id=quote_id,
            request=_request_of(Consent(**_consent_from(journal["consent"]))),
            action_hash=action_commitment(
                to_proposed(action), bytes.fromhex(journal["action_salt"])
            ),
            key=journal["idempotency_key"],
            reason=_OUTCOME_UNKNOWN,
            since=action.freshness.timestamp,
        )

    @property
    def source(self) -> str:
        """Account every quote debits."""
        return self._source

    def guarded(self, work: Callable[[BankRail, Verifier], _T]) -> _T:
        """Run ``work`` against the desk's bank and verifier under the desk lock.

        Args:
            work: Callable receiving the bank rail and the verifier.

        Returns:
            Whatever ``work`` returns.
        """
        with self._lock:
            return work(self.bank, self._verifier)

    @property
    def gate_public_key(self) -> bytes:
        """Raw Ed25519 public key that verifies certificates, seals and receipts."""
        return self._gate_pub

    @property
    def bank_public_key(self) -> bytes:
        """Raw Ed25519 public key that verifies the bank's funds statements."""
        return self._bank_pub

    @property
    def holder_keys(self) -> tuple[bytes, ...]:
        """Raw public keys trusted to approve quotes."""
        with self._lock:
            return self._holders

    def register_holder(self, public_key: bytes) -> bool:
        """Trust a holder key while none is registered.

        Args:
            public_key: Raw 32-byte Ed25519 public key.

        Returns:
            True when stored, False when a holder already exists.

        Raises:
            ValueError: If the key is not 32 bytes.
        """
        if type(public_key) is not bytes or len(public_key) != _KEY_LEN:
            raise ValueError("holder key must be 32 bytes")
        with self._lock:
            if self._holders:
                return False
            if self._state is not None:
                self._state.put("holders", json.dumps([_b64(public_key)]))
            self._holders = (public_key,)
            return True

    def record_intent(self, intent: Intent, signature: bytes) -> dict[str, Any]:
        """Record a holder-signed intent and sign a funds statement for it.

        The statement's nonce is the intent hash. The desk keeps only the
        statement's reference; the statement itself goes back to the holder.

        Args:
            intent: Amount, currency, payee and reference the holder signed.
            signature: The holder's Ed25519 signature over the intent bytes.

        Returns:
            The signed view with the intent id, hash, summary, the statement's
            reference, the statement and the bank's public key; or a denied
            dict with the reason.
        """
        summary = self._summary(intent)
        with self._lock:
            view = self._record_intent(intent, signature, summary)
            self._line("intent", view, summary)
            return view

    def intent_receipt(self, intent_id: str) -> dict[str, Any]:
        """Agent view of a recorded intent: fields and references only.

        Args:
            intent_id: Intent to read.

        Returns:
            Status (``signed``, ``unsettled`` or ``paid``), ids, hash, summary,
            the four fields, the statement's reference and the payment id; an
            unsettled intent also carries the idempotency key the bank has not
            settled and a ``detail`` sentence saying so. An unknown view when
            no such intent exists.
        """
        with self._lock:
            return self._intent_view(intent_id)

    def funds_challenge(self, intent_id: str) -> dict[str, Any]:
        """The one balance lookup the holder must prove for an intent.

        Args:
            intent_id: Recorded intent the proof is for.

        Returns:
            An open view with the host, path, nonce (the intent hash), notary
            address and key, and the revealed fields; an unknown view when no
            such intent exists; an unavailable view with the reason when the
            desk has no zkTLS setup or cannot prove the debit account.
        """
        with self._lock:
            if self._zktls is None:
                return _unavailable(intent_id, "zktls: not configured")
            found = self._intents.get(intent_id)
            if found is None:
                return {"status": "unknown", "intent_id": intent_id}
            try:
                session = self._zktls.challenge(self._source, found.hash)
            except ZktlsError as exc:
                return _unavailable(intent_id, str(exc))
            return {"status": "open", "intent_id": intent_id, **session}

    def record_funds_proof(self, intent_id: str, presentation: bytes) -> dict[str, Any]:
        """Verify a zkTLS balance proof and make it the intent's funds evidence.

        The verifier sees the balance; the desk keeps only the comparison
        with the intent's amount. A refused proof leaves the cooperative
        statement in place.

        Args:
            intent_id: Recorded intent the proof is for.
            presentation: The holder's TLSNotary presentation bytes.

        Returns:
            A proven view with the new evidence reference, the server and the
            session time; a denied view with the reason; or an unknown view
            when no such intent exists.
        """
        with self._lock:
            found = self._intents.get(intent_id)
            zktls = self._zktls
            if zktls is None:
                refusal: str | None = "zktls: not configured"
            elif found is None:
                return {"status": "unknown", "intent_id": intent_id}
            else:
                refusal = _proof_refusal(found)
            if refusal is not None or zktls is None or found is None:
                view = _denied_proof(intent_id, refusal or "zktls: not configured")
                return self._proof_line(found, view)
            snapshot = (found.hash, found.funds_ref)
        # The verifier child runs for up to its timeout; the desk stays open
        # meanwhile and the intent is checked again before anything is kept.
        try:
            proof = zktls.verify(presentation, self._source, found.hash, self._clock())
        except ZktlsError as exc:
            with self._lock:
                return self._proof_line(found, _denied_proof(intent_id, str(exc)))
        with self._lock:
            unchanged = (
                self._intents.get(intent_id) is found
                and _proof_refusal(found) is None
                and (found.hash, found.funds_ref) == snapshot
            )
            view = (
                self._keep_proof(intent_id, found, proof)
                if unchanged
                else _denied_proof(intent_id, "zktls: challenge changed")
            )
            return self._proof_line(found, view)

    def _proof_line(
        self, found: _Intent | None, view: dict[str, Any]
    ) -> dict[str, Any]:
        summary = "" if found is None else self._summary(found.intent)
        self._line("intent", view, summary)
        return view

    def _keep_proof(
        self, intent_id: str, found: _Intent, proof: BalanceProof
    ) -> dict[str, Any]:
        if proof.available_balance < found.intent.amount_cents:
            return _denied_proof(intent_id, "zktls: insufficient funds")
        funds = {
            "kind": "zktls",
            "evidence_ref": proof.evidence_ref,
            "presentation_sha256": proof.presentation_sha256,
            "server_name": BANK_HOST,
            "session_time": proof.session_time,
            "notary_key": proof.notary_key,
        }
        self._keep_intent(intent_id, found, funds_ref=proof.evidence_ref, funds=funds)
        return {
            "status": "proven",
            "intent_id": intent_id,
            "evidence_ref": proof.evidence_ref,
            "server": BANK_HOST,
            "session_time": proof.session_time,
        }

    def _summary(self, intent: Intent) -> str:
        return pay_summary(
            str(intent.amount_cents),
            intent.currency,
            intent.recipient,
            intent.reference,
            self._source,
        )

    @overload
    def reconcile(self) -> Reconciliation: ...

    @overload
    def reconcile(self, intent_id: str) -> dict[str, Any]: ...

    def reconcile(
        self, intent_id: str | None = None
    ) -> Reconciliation | dict[str, Any]:
        """Reconcile the whole desk with the bank, or settle one intent.

        Without an intent id: settles every journaled payment (see
        ``_settle_journal``), in quote order, then compares the transfers the
        bank lists from the debit account since the registry began with the
        sealed receipts. Reads only; the bank is never asked to move money.
        The view is kept as the latest reconciliation. A bank that cannot be
        read stops the settling and is named in ``error``; the comparison then
        does not run and writes nothing.

        With an intent id: see ``_reconcile_intent``.

        Args:
            intent_id: Intent to settle, or None for the whole desk.

        Returns:
            The ``Reconciliation``, or the intent's view.

        Raises:
            ValueError: Without an intent id, if the rail cannot list its
                transfers.
        """
        if intent_id is not None:
            return self._reconcile_intent(intent_id)
        ledger = self.bank
        if not isinstance(ledger, TransferLedger):
            raise ValueError("reconcile: the rail cannot list transfers")
        with self._lock:
            return self._reconcile_bank(ledger)

    def latest_reconciliation(self) -> dict[str, Any] | None:
        """View of the newest reconciliation, or None before the first one."""
        with self._lock:
            latest = self._reconciliation
            return None if latest is None else json.loads(json.dumps(latest))

    def _reconcile_bank(self, ledger: TransferLedger) -> Reconciliation:
        resolved, pending, error = self._settle_journals(ledger)
        transfers = certified = 0
        unbacked: tuple[str, ...] = ()
        missing: tuple[str, ...] = ()
        if error is None:
            try:
                listed = ledger.transfers(self._source, self._genesis)
            except RailError as exc:
                error = str(exc)
            else:
                sealed = self._sealed(ledger.rail)
                certified, unbacked, missing = compare(listed, sealed, ledger.rail)
                transfers = sum(1 for t in listed if t.status != CANCELED)
        report = Reconciliation(
            ledger.rail,
            ledger.provider,
            self._genesis,
            self._clock(),
            transfers,
            certified,
            unbacked,
            missing,
            resolved,
            pending,
            error,
        )
        view = report.view()
        if self._state is not None:
            self._state.put("reconciliation", json.dumps(view))
        self._reconciliation = view
        return report

    def _sealed(self, rail: str) -> dict[str, tuple[str, bool]]:
        """Each stored receipt on a rail: its jti and whether its entry is ours."""
        sealed: dict[str, tuple[str, bool]] = {}
        for receipt in self._proofs.values():
            bank = _jws_payload(receipt["sd"].split("~")[0]).get("bank")
            if bank is None or bank.get("rail") != rail:
                continue
            entry = LogEntry(**receipt["registry"]["entry"])
            ours = 0 < entry.seq <= self.registry.size()
            ours = ours and self.registry.entry(entry.seq) == entry
            jti = _jws_payload(receipt["certificate"])["jti"]
            sealed[receipt["payment_id"]] = (jti, ours)
        return sealed

    def _settle_journals(
        self, ledger: TransferLedger
    ) -> tuple[tuple[str, ...], tuple[str, ...], str | None]:
        """Settle every journaled payment the bank can now answer for."""
        if self._state is None:
            return (), (), None
        resolved: list[str] = []
        pending: list[str] = []
        error: str | None = None
        for quote_id, value in sorted(self._state.records("pending")):
            if error is not None or not self.registry.has_room():
                pending.append(quote_id)
                continue
            try:
                outcome = self._settle_journal(ledger, quote_id, json.loads(value))
            except RailError as exc:
                error = str(exc)
                outcome = None
            if outcome is None:
                pending.append(quote_id)
            else:
                resolved.append(f"{quote_id} -> {outcome}")
        return tuple(resolved), tuple(pending), error

    def _settle_journal(
        self, ledger: TransferLedger, quote_id: str, journal: dict[str, Any]
    ) -> str | None:
        """Settle one journaled payment by a lookup of its idempotency key.

        A complete transfer that matches the journal field by field becomes
        the sealed payment; no transfer (or a canceled one) once the
        certificate has expired becomes a sealed "not paid". Anything else,
        a transfer still awaiting approval included, stays pending.

        Returns:
            The transfer id, ``not paid``, or None while it stays pending.

        Raises:
            RailError: If the bank cannot be read.
        """
        transfer = ledger.transfer_by_key(journal["idempotency_key"])
        if transfer is not None and transfer.status == "complete":
            held = self._matching(journal, transfer)
            if held is None:
                return None
            self._seal_transfer(quote_id, journal, held)
            return held.payment_id
        absent = transfer is None or transfer.status == CANCELED
        if absent and self._clock() > journal["expires_at"]:
            self._seal_not_paid(quote_id, journal)
            return "not paid"
        return None

    def _matching(
        self, journal: dict[str, Any], transfer: BankTransfer
    ) -> Payment | None:
        """The bank's payment for a found transfer, when it is the journal's."""
        key = journal["idempotency_key"]
        request = _request_of(Consent(**_consent_from(journal["consent"])))
        if (transfer.idempotency_key, transfer.amount_cents) != (
            key,
            request.amount_cents,
        ):
            return None
        # The rail's own lookup compares the accounts and currency it holds.
        try:
            held = self.bank.reconcile(request, _journal_hash(journal), key)
        except RailError as exc:
            if str(exc) in (_DIFFERS, _NOT_COMPLETE):
                return None
            raise RailError("bank: unavailable") from None
        except ValueError:
            return None
        if held is None or held.payment_id != transfer.transfer_id:
            return None
        return held if _same_payment(held, request, key) else None

    def _seal_transfer(
        self, quote_id: str, journal: dict[str, Any], held: Payment
    ) -> None:
        """Make a journaled transfer the bank completed a sealed payment."""
        consent = Consent(**_consent_from(journal["consent"]))
        action = _action_from(journal["action"])
        salt = bytes.fromhex(journal["action_salt"])
        certificate = journal["certificate"]
        payment = Payment(
            held.payment_id,
            consent.source,
            consent.recipient,
            consent.amount_cents,
            consent.currency,
            consent.reference,
            _journal_hash(journal),
            rail=self.bank.rail,
            provider=held.provider,
            status=held.status,
            idempotency_key=journal["idempotency_key"],
        )
        result: dict[str, Any] = {
            "status": "confirmed",
            "quote_id": quote_id,
            "payment_id": payment.payment_id,
            "reason": _RECONCILED,
        }
        # The registry body is the ordinary one, so inclusion checks hold.
        body = _result_body({**result, "reason": "ok: executed"})
        iid = journal["intent_id"] or ""
        bound = self._intents.get(iid)
        changes = _paid_changes(bound, quote_id, payment.payment_id)

        def work() -> tuple[InclusionProof, dict[str, Any]]:
            seq, seal = self._append("execution", body)
            proof = self.registry.prove(seq)
            receipt = proof_receipt(
                payment.payment_id,
                certificate,
                action,
                DESK_POLICY,
                consent,
                base64.b64decode(journal["holder_key"]),
                LogEntry(seq, "execution", body),
                proof,
                seal,
                self._gate_key,
                self._salts,
                action_salt=salt,
                payment=payment,
                funds=_funds_view(bound),
            )
            self._put("receipt", payment.payment_id, receipt)
            self._put("result", payment.payment_id, result)
            self._put("quote", quote_id, result)
            if bound is not None and changes:
                self._put("intent", iid, _intent_record(_replace(bound, changes)))
            self._drop("pending", quote_id)
            return proof, receipt

        proof, receipt = self._durably(work)
        self._proofs[payment.payment_id] = receipt
        self._receipts[payment.payment_id] = result
        if bound is not None:
            for name, value in changes.items():
                setattr(bound, name, value)
        self._close_quote(quote_id, result)
        forensic = forensic_of(
            action,
            DESK_POLICY,
            certificate,
            self._gate_pub,
            consent=consent,
            proof=proof,
            salt=salt,
            payment=payment,
        )
        self._emit("confirm", result, consent, None, forensic)

    def _seal_not_paid(self, quote_id: str, journal: dict[str, Any]) -> None:
        """Seal that an expired certificate moved no money; release its intent."""
        result: dict[str, Any] = {
            "status": "denied",
            "quote_id": quote_id,
            "reason": _NOT_PAID,
            "payment_id": None,
        }
        iid = journal["intent_id"] or ""
        bound = self._intents.get(iid)
        changes: dict[str, Any] = {}
        if bound is not None and _unsettled_by(bound, quote_id):
            changes = {"unsettled": None}

        def work() -> None:
            self._append("denial", _result_body(result))
            self._put("quote", quote_id, result)
            if bound is not None and changes:
                self._put("intent", iid, _intent_record(_replace(bound, changes)))
            self._drop("pending", quote_id)

        self._durably(work)
        if bound is not None and changes:
            bound.unsettled = None
        self._close_quote(quote_id, result)

    def _journal_of(self, quote_id: str) -> dict[str, Any] | None:
        if self._state is None:
            return None
        value = self._state.record("pending", quote_id)
        return None if value is None else dict(json.loads(value))

    def _reconcile_intent(self, intent_id: str) -> dict[str, Any]:
        """Settle an unsettled intent by one bank lookup of its idempotency key.

        A transfer found complete and matching spends the intent: the quote
        that sent it becomes confirmed and an execution entry is sealed. No
        transfer under the key releases the intent for a new quote, but only
        once ``SETTLE_WINDOW_S`` have passed since the attempt; earlier it
        stays unsettled. A differing transfer, or a lookup that cannot tell,
        leaves it unsettled.

        Args:
            intent_id: Intent to settle.

        Returns:
            The intent's view after the lookup; an intent that is not
            unsettled is returned as it stands, with no bank call.
        """
        with self._lock:
            found = self._intents.get(intent_id)
            if found is None or found.unsettled is None:
                return self._intent_view(intent_id)
            pending = found.unsettled
            if not self.registry.has_room():
                return self._intent_view(intent_id)
            try:
                payment = self.bank.reconcile(
                    pending.request, pending.action_hash, pending.key
                )
            except (RailError, ValueError) as exc:
                still = dataclasses.replace(pending, reason=str(exc))
                self._keep_intent(intent_id, found, unsettled=still)
                return self._intent_view(intent_id)
            if payment is None and self._clock() - pending.since < SETTLE_WINDOW_S:
                still = dataclasses.replace(pending, reason=_NOT_YET)
                self._keep_intent(intent_id, found, unsettled=still)
                return self._intent_view(intent_id)
            journal = self._journal_of(pending.quote_id)
            if payment is None:
                self._keep_intent(intent_id, found, unsettled=None)
            elif journal is not None:
                # One settlement for both paths: a receipt the reconciler counts.
                self._seal_transfer(pending.quote_id, journal, payment)
            else:
                self._settle(intent_id, found, pending.quote_id, payment)
            return self._intent_view(intent_id)

    def _settle(
        self, intent_id: str, found: _Intent, quote_id: str, payment: Payment
    ) -> None:
        """Make the transfer a lookup found the intent's payment, durably."""
        result: dict[str, Any] = {
            "status": "confirmed",
            "quote_id": quote_id,
            "reason": "ok: reconciled",
            "payment_id": payment.payment_id,
        }
        paid = dataclasses.replace(found, payment_id=payment.payment_id, unsettled=None)

        def work() -> None:
            self._append("execution", _result_body(result))
            self._put("intent", intent_id, _intent_record(paid))
            self._put("result", payment.payment_id, result)
            self._put("quote", quote_id, result)
            self._drop("pending", quote_id)

        self._durably(work)
        found.payment_id, found.unsettled = payment.payment_id, None
        self._receipts[payment.payment_id] = result
        self._close_quote(quote_id, result)

    def _keep_intent(self, intent_id: str, found: _Intent, **changes: Any) -> None:
        """Write an intent's new fields through, then adopt them in memory."""
        self._put(
            "intent", intent_id, _intent_record(dataclasses.replace(found, **changes))
        )
        for name, value in changes.items():
            setattr(found, name, value)

    def _close_quote(self, quote_id: str, result: dict[str, Any]) -> None:
        record = self._quotes.get(quote_id)
        if record is None:
            self._closed[quote_id] = result
            return
        record.status = result["status"]
        record.result = result

    def _intent_view(self, intent_id: str) -> dict[str, Any]:
        found = self._intents.get(intent_id)
        if found is None:
            return {"status": "unknown", "intent_id": intent_id}
        i = found.intent
        status = "signed" if found.payment_id is None else "paid"
        if found.unsettled is not None:
            status = "unsettled"
        view: dict[str, Any] = {
            "status": status,
            "intent_id": intent_id,
            "intent_hash": found.hash,
            "summary": self._summary(i),
            "amount_cents": i.amount_cents,
            "currency": i.currency,
            "recipient": i.recipient,
            "reference": i.reference,
            "evidence_ref": found.funds_ref,
            "payment_id": found.payment_id,
        }
        if found.unsettled is not None:
            view["idempotency_key"] = found.unsettled.key
            view["detail"] = _unsettled_detail(found.unsettled)
        return view

    def quote(
        self,
        recipient: str,
        amount_cents: int,
        currency: str,
        reference: str,
        intent_id: str | None = None,
    ) -> dict[str, Any]:
        """Open a quote the holder can approve.

        Args:
            recipient: Payee account.
            amount_cents: Amount in integer cents.
            currency: Currency code.
            reference: Payment reference.
            intent_id: Recorded intent the quote is bound to, or None. A
                bound quote is checked against that intent at the gate.

        Returns:
            The quoted view, or a denied dict when a field is malformed or
            the intent is unknown.
        """
        with self._lock:
            if intent_id is not None and intent_id not in self._intents:
                unknown = {
                    "status": "denied",
                    "reason": "intent: unknown",
                    "intent_id": intent_id,
                }
                summary = pay_summary(
                    str(amount_cents), currency, recipient, reference, self._source
                )
                self._line("quote", unknown, summary)
                return unknown
            consent = Consent(
                amount_cents,
                currency,
                recipient,
                reference,
                self._source,
                self._nonces(),
                self._clock() + self._ttl,
                b"",
            )
            try:
                consent_bytes(consent)
            except ValueError:
                denied = {"status": "denied", "reason": "consent: malformed"}
                self._emit("quote", denied, consent)
                return denied
            if self._state is not None:
                self._state.put("quote_seq", str(self._seq + 1))
            self._seq += 1
            record = _Quote(self._seq, consent, intent_id=intent_id)
            self._quotes[_quote_id(self._seq)] = record
            view = self._quoted_view(record)
            self._emit("quote", view, consent)
            return view

    def expired(self, consent_expires_at: int) -> bool:
        """Whether the desk's clock is past a quote's deadline (the approve rule)."""
        return self._clock() > consent_expires_at

    def pending(self) -> list[dict[str, Any]]:
        """Quotes still awaiting approval, in id order."""
        with self._lock:
            return [
                self._quoted_view(q)
                for q in self._quotes.values()
                if q.status == "quoted"
            ]

    def approve(self, quote_id: str, approval: HolderApproval) -> dict[str, Any]:
        """Record the holder's approval of a quote.

        Args:
            quote_id: Quote to approve.
            approval: A one-time key, its signature over the quote's consent
                bytes, and the holder key's certificate of that key.

        Returns:
            The approved view, the quote's current view when it is no longer
            open, an expired view past its deadline, or a denied dict for a
            bad signature or a reused key (the quote stays open).
        """
        with self._lock:
            record = self._quotes.get(quote_id)
            if record is None:
                return _unknown(quote_id)
            if record.status != "quoted":
                return self._view(quote_id, record)
            if self._clock() > record.consent.expires_at:
                record.status = "expired"
                view = self._view(quote_id, record)
                self._emit("approve", view, record.consent)
                return view
            signed = with_approval(record.consent, approval)
            if not verify_signature(signed, self._holders):
                denied = {
                    "status": "denied",
                    "reason": "consent: bad signature",
                    "quote_id": quote_id,
                }
                self._emit("approve", denied, record.consent)
                return denied
            # Read-only: the gate stays the authority and consumes at confirm.
            if (
                self._ledger.key_used(signed.consent_key)
                or signed.consent_key in self._holders
            ):
                reused = {
                    "status": "denied",
                    "reason": "consent: key reused",
                    "quote_id": quote_id,
                }
                self._emit("approve", reused, record.consent)
                return reused
            record.consent = signed
            record.status = "approved"
            view = self._view(quote_id, record)
            self._emit("approve", view, signed)
            return view

    def confirm(self, quote_id: str) -> dict[str, Any]:
        """Run the approved payment through the gate, at most once.

        Args:
            quote_id: Quote to execute.

        A quote naming no intent on a desk that requires one, or naming an
        intent that already paid, whose last transfer the bank has not
        settled, or whose zkTLS balance proof is older than ``PROOF_TTL_S``,
        is denied without a gate run; the denial is still appended to the
        registry and sealed. An expired proof leaves the intent signed, so
        the holder can prove the balance again.

        Args:
            quote_id: Quote to execute.

        Returns:
            The stored result; later calls return it unchanged.
        """
        with self._lock:
            record = self._quotes.get(quote_id)
            if record is None:
                return _unknown(quote_id)
            if record.status != "approved":
                return self._view(quote_id, record)
            iid = record.intent_id
            bound = None if iid is None else self._intents[iid]
            refusal = None
            if self._require_intent and bound is None:
                refusal = "intent: missing"
            elif bound is not None and bound.payment_id is not None:
                refusal = "intent: already used"
            elif bound is not None and bound.unsettled is not None:
                refusal = "intent: unsettled"
            elif bound is not None and _proof_expired(bound, self._clock()):
                refusal = "zktls: proof expired"
            if not self.registry.has_room():
                return {
                    "status": "denied",
                    "reason": "registry: full",
                    "quote_id": quote_id,
                }
            if refusal is not None:
                return self._refuse(quote_id, record, refusal)
            return self._execute(quote_id, record, bound)

    def status(self, quote_id: str) -> dict[str, Any]:
        """Latest view of a quote."""
        with self._lock:
            record = self._quotes.get(quote_id)
            if record is not None:
                return self._view(quote_id, record)
            closed = self._closed.get(quote_id)
            return _unknown(quote_id) if closed is None else dict(closed)

    def receipt(self, payment_id: str) -> dict[str, Any]:
        """Stored confirm result of a payment."""
        with self._lock:
            found = self._receipts.get(payment_id)
            if found is None:
                return {"status": "unknown", "payment_id": payment_id}
            return dict(found)

    def proof_receipt(self, payment_id: str) -> dict[str, Any] | None:
        """Holder copy of a confirmed payment's proof receipt.

        Args:
            payment_id: Executed payment.

        Returns:
            A deep copy of the receipt with every Disclosure, or None when the
            payment has no receipt.
        """
        with self._lock:
            found = self._proofs.get(payment_id)
            return None if found is None else json.loads(json.dumps(found))

    def latest_seal(self) -> dict[str, Any] | None:
        """View of the newest registry seal, or None before the first append."""
        with self._lock:
            seals = self.registry.anchors()
            return seal_view(seals[-1]) if seals else None

    def _record_intent(
        self, intent: Intent, signature: bytes, summary: str
    ) -> dict[str, Any]:
        if not self._holders:
            return _denied_intent("intent: no holder")
        try:
            confirmed_intent(self._holders[0], intent, signature)
        except IntentError as exc:
            malformed = str(exc) == "intent: malformed"
            return _denied_intent(
                "intent: malformed" if malformed else "intent: bad signature"
            )
        digest = intent_hash(intent)
        if digest in self._intent_hashes:
            return _denied_intent("intent: already recorded")
        try:
            balance = self.bank.get_balance(self._source)
        except RailError as exc:
            return _denied_intent(str(exc))
        if balance < intent.amount_cents:
            return _denied_intent("state: insufficient funds")
        state = sign_state(
            self._bank_key,
            subject=self._source,
            statement="funds-sufficient",
            balance_cents=balance,
            currency=intent.currency,
            nonce=digest,
            issued_at=self._clock(),
            ttl_s=_STATEMENT_TTL_S,
        )
        funds_ref = opaque_cooperative_ref(state)
        intent_id = f"i:{len(self._intents) + 1:06d}"
        stored = _Intent(
            intent, digest, funds_ref, opaque_intent_ref(intent, signature)
        )
        self._put("intent", intent_id, _intent_record(stored))
        self._intents[intent_id] = stored
        self._intent_hashes.add(digest)
        statement = dataclasses.asdict(state)
        statement["signature"] = base64.b64encode(state.signature).decode("ascii")
        return {
            "status": "signed",
            "intent_id": intent_id,
            "intent_hash": digest,
            "summary": summary,
            "evidence_ref": funds_ref,
            "state": statement,
            "bank_key": base64.b64encode(self._bank_pub).decode("ascii"),
        }

    def _append(self, kind: str, body: str) -> tuple[int, Anchor]:
        # Every entry is sealed right away, so the newest seal covers the log.
        seq = self.registry.append(kind, body)
        return seq, self.registry.anchor(self._clock())

    def _put(self, kind: str, key: str, value: Any) -> None:
        if self._state is not None:
            self._state.put_record(kind, key, _dumps(value))

    def _drop(self, kind: str, key: str) -> None:
        if self._state is not None:
            self._state.drop_record(kind, key)

    def _durably(self, work: Callable[[], _T]) -> _T:
        """Run ``work`` as one commit; memory changes only after it succeeds.

        A failed commit rolls the registry's rows back but not its memory, so
        the registry is reloaded from the store before the error propagates.
        """
        state = self._state
        if state is None:
            return work()
        try:
            with state.transaction():
                return work()
        except BaseException:
            self.registry = Registry(
                keypair=(self._gate_key, self._gate_pub), state=state
            )
            raise

    def _refuse(self, quote_id: str, record: _Quote, reason: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "denied",
            "quote_id": quote_id,
            "reason": reason,
            "payment_id": None,
        }

        def work() -> None:
            self._append("denial", _result_body(result))
            self._put("quote", quote_id, result)

        self._durably(work)
        record.status = "denied"
        record.result = result
        self._emit("confirm", result, record.consent)
        return dict(result)

    def _journal(
        self, quote_id: str, record: _Quote
    ) -> Callable[[str, CavaAction, bytes], None]:
        """Write-ahead record of an issued certificate, on disk before the bank."""
        state = self._state
        c = record.consent

        def issued(certificate: str, action: CavaAction, salt: bytes) -> None:
            if state is None:
                return
            claims = _jws_payload(certificate)
            entry = {
                "quote_id": quote_id,
                "intent_id": record.intent_id,
                "certificate": certificate,
                "action": json.loads(canonical_bytes(action)),
                "action_salt": salt.hex(),
                "consent": _consent_record(c),
                "holder_key": _b64(self._holder_of(c)),
                "idempotency_key": idempotency_key(claims["jti"]),
                "expires_at": claims["exp"],
            }
            state.put_record("pending", quote_id, _dumps(entry))

        return issued

    def _holder_of(self, consent: Consent) -> bytes:
        return next(k for k in self._holders if verify_signature(consent, (k,)))

    def _execute(
        self, quote_id: str, record: _Quote, bound: _Intent | None
    ) -> dict[str, Any]:
        c = record.consent
        now = self._clock()
        if bound is None:
            intent = Intent(c.amount_cents, c.currency, c.recipient, c.reference)
            refs: tuple[str, ...] = (quote_id,)
        else:
            intent = bound.intent
            refs = (quote_id, bound.intent_ref, bound.funds_ref)
        salt = self._action_salts()
        request = RunRequest(
            call=RawCall(
                runtime="mcp",
                executable="bank.pay",
                operation="transfer",
                args=(
                    ("amount", str(c.amount_cents)),
                    ("currency", c.currency),
                    ("from", c.source),
                    ("to", c.recipient),
                    ("ref", c.reference),
                ),
                category="payments",
                evidence_refs=refs,
                reversible=False,
            ),
            policy=DESK_POLICY,
            intent=intent,
            private_key=self._gate_key,
            mode=Mode.ENFORCE,
            now=now,
            nonce=self._nonces(),
            timestamp=now,
            scope=PAY_SCOPE,
            salt=salt,
            reasoning_commitment=reasoning_commitment(()),
            revocation_index=record.number % _REVOCATION_BITS,
            consent=c,
            holder_keys=self._holders,
            consents=self._ledger,
        )
        # The verifier runs outside any store transaction, so the certificate
        # id it spends is on disk before the bank is called.
        try:
            outcome = run_governed(
                request, self.bank, self._verifier, self._journal(quote_id, record)
            )
        except Exception as exc:
            # Only the type: a message could carry consent fields or keys.
            _log.error(
                "payment outcome unknown for %s (%s)", quote_id, type(exc).__name__
            )
            return self._unknown_outcome(quote_id, record, bound, request, salt)
        paid = outcome.reason == "ok: executed" and outcome.payment is not None
        payment_id = outcome.payment.payment_id if paid and outcome.payment else None
        result: dict[str, Any] = {
            "status": "confirmed" if paid else "denied",
            "quote_id": quote_id,
            "reason": outcome.reason,
            "payment_id": payment_id,
        }
        changes: dict[str, Any] = {}
        if bound is not None and payment_id is not None:
            changes = {"payment_id": payment_id}
        elif bound is not None and outcome.reason in _UNSETTLED:
            changes = {
                "unsettled": _unsettled(quote_id, c, request, salt, outcome.reason)
            }
        body = _result_body(result)
        kind = "execution" if paid else "denial"

        def work() -> tuple[InclusionProof, dict[str, Any] | None]:
            if self._state is not None:
                self._state.prune(now)
            seq, seal = self._append(kind, body)
            proof = self.registry.prove(seq)
            receipt = None
            if payment_id is not None:
                entry = LogEntry(seq, kind, body)
                receipt = self._receipt_of(
                    payment_id, outcome, c, bound, entry, proof, seal
                )
                self._put("result", payment_id, result)
                if receipt is not None:
                    self._put("receipt", payment_id, receipt)
            if bound is not None and changes:
                iid = record.intent_id or ""
                after = dataclasses.replace(bound, **changes)
                self._put("intent", iid, _intent_record(after))
            self._put("quote", quote_id, result)
            # Only a definite outcome closes the journal; an unsettled
            # transfer stays visible to the reconciler.
            if outcome.reason not in _UNSETTLED:
                self._drop("pending", quote_id)
            return proof, receipt

        try:
            proof, receipt = self._durably(work)
        except BaseException:
            # The bank may have moved the money; the journal stays on disk.
            self._hold(quote_id, record, bound, request, salt)
            raise
        record.status = result["status"]
        record.result = result
        if payment_id is not None:
            self._receipts[payment_id] = result
            if receipt is not None:
                self._proofs[payment_id] = receipt
        if bound is not None:
            for name, value in changes.items():
                setattr(bound, name, value)
        forensic = None
        if outcome.action is not None:
            forensic = forensic_of(
                outcome.action,
                DESK_POLICY,
                outcome.certificate,
                self._gate_pub,
                consent=c,
                proof=proof,
                salt=outcome.salt,
                payment=outcome.payment,
            )
        self._emit("confirm", result, c, outcome.event, forensic)
        return dict(result)

    def _receipt_of(
        self,
        payment_id: str,
        outcome: RunResult,
        c: Consent,
        bound: _Intent | None,
        entry: LogEntry,
        proof: InclusionProof,
        seal: Anchor,
    ) -> dict[str, Any] | None:
        if not (outcome.certificate and outcome.action and outcome.salt):
            return None
        # The bank already paid: a receipt that cannot be built must not
        # turn the confirm into an error. The payment simply has none.
        try:
            return proof_receipt(
                payment_id,
                outcome.certificate,
                outcome.action,
                DESK_POLICY,
                c,
                self._holder_of(c),
                entry,
                proof,
                seal,
                self._gate_key,
                self._salts,
                action_salt=outcome.salt,
                payment=outcome.payment,
                funds=_funds_view(bound),
            )
        except Exception as exc:
            # Only the type: a message could carry consent fields or keys.
            _log.error("receipt not built for %s (%s)", payment_id, type(exc).__name__)
            return None

    def _hold(
        self,
        quote_id: str,
        record: _Quote,
        bound: _Intent | None,
        request: RunRequest,
        salt: bytes,
    ) -> None:
        """Memory only: what a restart would read from the kept journal."""
        record.status = "denied"
        record.result = _outcome_unknown(quote_id)
        if bound is not None and bound.payment_id is None:
            bound.unsettled = _unsettled(
                quote_id, record.consent, request, salt, _OUTCOME_UNKNOWN
            )

    def _unknown_outcome(
        self,
        quote_id: str,
        record: _Quote,
        bound: _Intent | None,
        request: RunRequest,
        salt: bytes,
    ) -> dict[str, Any]:
        """Close a confirm whose run failed: the bank may hold the transfer."""
        result = _outcome_unknown(quote_id)
        unsettled = None
        if bound is not None:
            unsettled = _unsettled(
                quote_id, record.consent, request, salt, _OUTCOME_UNKNOWN
            )

        def work() -> None:
            self._append("denial", _result_body(result))
            if bound is not None:
                after = dataclasses.replace(bound, unsettled=unsettled)
                self._put("intent", record.intent_id or "", _intent_record(after))
            self._put("quote", quote_id, result)

        try:
            self._durably(work)
        except BaseException:
            self._hold(quote_id, record, bound, request, salt)
            raise
        record.status = "denied"
        record.result = result
        if bound is not None:
            bound.unsettled = unsettled
        self._emit("confirm", result, record.consent)
        return dict(result)

    def _emit(
        self,
        step: str,
        view: dict[str, Any],
        consent: Consent,
        event: DecisionEvent | None = None,
        forensic: dict[str, Any] | None = None,
    ) -> None:
        summary = pay_summary(
            str(consent.amount_cents),
            consent.currency,
            consent.recipient,
            consent.reference,
            consent.source,
        )
        self._line(step, view, summary, event, forensic)

    def _line(
        self,
        step: str,
        view: dict[str, Any],
        summary: str,
        event: DecisionEvent | None = None,
        forensic: dict[str, Any] | None = None,
    ) -> None:
        if self._publish is not None:
            self._publish(desk_line(step, view, summary, event, forensic))

    def _quoted_view(self, record: _Quote) -> dict[str, Any]:
        c = record.consent
        cents = c.amount_cents
        return {
            "status": "quoted",
            "quote_id": _quote_id(record.number),
            "summary": pay_summary(
                str(cents), c.currency, c.recipient, c.reference, c.source
            ),
            "consent": {
                "amount_cents": cents,
                "currency": c.currency,
                "expires_at": c.expires_at,
                "nonce": c.nonce,
                "recipient": c.recipient,
                "reference": c.reference,
                "source": c.source,
            },
            "intent_id": record.intent_id,
        }

    def _view(self, quote_id: str, record: _Quote) -> dict[str, Any]:
        if record.status == "quoted":
            return self._quoted_view(record)
        if record.result is not None:
            return dict(record.result)
        return {"status": record.status, "quote_id": quote_id}


def _unsettled(
    quote_id: str, consent: Consent, request: RunRequest, salt: bytes, reason: str
) -> _Unsettled:
    """What a later lookup needs to settle the transfer a run left open.

    Everything comes from the run's own inputs, so it is known even when the
    run failed before it returned: the certificate's id is the run's nonce,
    and the action hash is the canonized call under the run's salt.
    """
    action = canonize(request.call, request.nonce, request.timestamp)
    return _Unsettled(
        quote_id=quote_id,
        request=_request_of(consent),
        action_hash=action_commitment(to_proposed(action), salt),
        key=idempotency_key(request.nonce),
        reason=reason,
        since=request.now,
    )


def _request_of(consent: Consent) -> PaymentRequest:
    return PaymentRequest(
        from_acct=consent.source,
        to_acct=consent.recipient,
        amount_cents=consent.amount_cents,
        currency=consent.currency,
        ref=consent.reference,
    )


def _outcome_unknown(quote_id: str) -> dict[str, Any]:
    return {
        "status": "denied",
        "quote_id": quote_id,
        "reason": _OUTCOME_UNKNOWN,
        "payment_id": None,
    }


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _consent_record(consent: Consent) -> dict[str, Any]:
    record = dataclasses.asdict(consent)
    for name in _BYTE_FIELDS:
        record[name] = _b64(record[name])
    return record


def _consent_from(record: dict[str, Any]) -> dict[str, Any]:
    return {
        **record,
        **{name: base64.b64decode(record[name]) for name in _BYTE_FIELDS},
    }


def _action_from(record: dict[str, Any]) -> CavaAction:
    """Inverse of ``canonical_bytes`` read back as JSON."""
    return CavaAction(
        version=record["version"],
        runtime=record["runtime"],
        executable=record["executable"],
        operation=record["operation"],
        category=record["category"],
        targets=tuple(record["targets"]),
        reversible=record["reversible"],
        freshness=Freshness(**record["freshness"]),
        evidence_refs=tuple(record["evidence_refs"]),
    )


def _jws_payload(token: str) -> dict[str, Any]:
    """Claims of a token the desk's gate signed; read, not verified."""
    part = token.split(".")[1]
    payload: dict[str, Any] = json.loads(
        base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    )
    return payload


def _journal_hash(journal: dict[str, Any]) -> str:
    """The salted action hash the journaled certificate signed."""
    action = _action_from(journal["action"])
    return action_commitment(to_proposed(action), bytes.fromhex(journal["action_salt"]))


def _same_payment(held: Payment, request: PaymentRequest, key: str) -> bool:
    """Whether the bank's payment is the request, complete, under the key."""
    return (
        held.from_acct,
        held.to_acct,
        held.amount_cents,
        held.currency,
        held.ref,
        held.idempotency_key,
        held.status,
    ) == (
        request.from_acct,
        request.to_acct,
        request.amount_cents,
        request.currency,
        request.ref,
        key,
        "complete",
    )


def _unsettled_by(found: _Intent, quote_id: str) -> bool:
    return found.unsettled is not None and found.unsettled.quote_id == quote_id


def _paid_changes(
    found: _Intent | None, quote_id: str, payment_id: str
) -> dict[str, Any]:
    """An intent's new fields once a transfer under its certificate moved.

    The intent may already have been released by a lookup that found nothing,
    or have paid since; a payment it already holds is never replaced.
    """
    if found is None:
        return {}
    changes: dict[str, Any] = {}
    if found.payment_id is None:
        changes["payment_id"] = payment_id
    if _unsettled_by(found, quote_id):
        changes["unsettled"] = None
    return changes


def _replace(found: _Intent, changes: dict[str, Any]) -> _Intent:
    return dataclasses.replace(found, **changes)


def _intent_record(found: _Intent) -> dict[str, Any]:
    """Every field of a stored intent, as JSON-ready values."""
    return dataclasses.asdict(found)


def _intent_from(record: dict[str, Any]) -> _Intent:
    """Inverse of ``_intent_record``."""
    pending = record["unsettled"]
    return _Intent(
        intent=Intent(**record["intent"]),
        hash=record["hash"],
        funds_ref=record["funds_ref"],
        intent_ref=record["intent_ref"],
        payment_id=record["payment_id"],
        unsettled=None
        if pending is None
        else _Unsettled(**{**pending, "request": PaymentRequest(**pending["request"])}),
        funds=record["funds"],
    )


def _unsettled_detail(pending: _Unsettled) -> str:
    """The holder's sentence for an intent the bank has not settled."""
    key = pending.key
    if pending.reason == _DIFFERS:
        return (
            f"The bank holds a transfer under {key} that differs from this "
            f"payment ({_DIFFERS}). This intent pays nothing more until the "
            "operator checks that transfer at the bank."
        )
    if pending.reason == _NOT_YET:
        return (
            f"The bank holds no transfer under {key} yet, and one may still "
            "commit. This intent pays nothing more until a lookup at least "
            f"{SETTLE_WINDOW_S} s after the attempt still finds nothing; try "
            "again later."
        )
    return (
        f"The bank has not confirmed whether transfer {key} went through "
        f"({pending.reason}). This intent pays nothing more until a lookup by "
        "that idempotency key settles it."
    )


def _funds_view(bound: _Intent | None) -> dict[str, Any] | None:
    """The receipt's funds evidence: never the balance or the bank account."""
    if bound is None:
        return None
    if bound.funds is not None:
        return dict(bound.funds)
    return {
        "kind": "cooperative",
        "evidence_ref": bound.funds_ref,
        "presentation_sha256": None,
        "server_name": None,
        "session_time": None,
        "notary_key": None,
    }


def _proof_expired(bound: _Intent, now: int) -> bool:
    """A balance proven too long ago no longer says the funds are there."""
    funds = bound.funds
    if funds is None or funds.get("kind") != "zktls":
        return False
    return bool(now - funds["session_time"] > PROOF_TTL_S)


def _unavailable(intent_id: str, reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "intent_id": intent_id, "reason": reason}


def _proof_refusal(found: _Intent) -> str | None:
    if found.payment_id is not None:
        return "intent: already used"
    # A transfer may already carry the current reference in its certificate.
    if found.unsettled is not None:
        return "intent: unsettled"
    return None


def _denied_proof(intent_id: str, reason: str) -> dict[str, Any]:
    return {"status": "denied", "intent_id": intent_id, "reason": reason}


def _quote_id(number: int) -> str:
    return f"q:{number:06d}"


def _unknown(quote_id: str) -> dict[str, Any]:
    return {"status": "unknown", "quote_id": quote_id}


def _denied_intent(reason: str) -> dict[str, Any]:
    return {"status": "denied", "reason": reason}


def _result_body(result: dict[str, Any]) -> str:
    return json.dumps(
        {k: result[k] for k in ("payment_id", "quote_id", "reason", "status")},
        sort_keys=True,
        separators=(",", ":"),
    )
