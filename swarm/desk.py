"""Payment desk: holder intent, quote, holder approval, gated confirm, receipt."""

import base64
import dataclasses
import json
import logging
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from bank.api import RailError
from bank.rail import SANDBOX, BankRail
from bank.verifier import Verifier
from evidence.cooperative import sign_state
from evidence.seams import opaque_cooperative_ref, opaque_intent_ref
from gate.cava import ACTION_SALT_LEN
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
from gate.registry import Anchor, LogEntry, Registry
from gate.shim import Mode, RawCall
from mandate.client import RunRequest, run_governed
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
_T = TypeVar("_T")


@dataclass
class _Quote:
    number: int
    consent: Consent
    status: str = "quoted"
    result: dict[str, Any] | None = None
    intent_id: str | None = None


@dataclass
class _Intent:
    intent: Intent
    hash: str
    funds_ref: str
    intent_ref: str
    payment_id: str | None = None


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
    ) -> None:
        self.bank = bank
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
        self.registry = Registry(keypair=(gate_key, self._gate_pub))
        self._ledger = ConsentLedger()
        self._holders: tuple[bytes, ...] = ()
        self._quotes: dict[str, _Quote] = {}
        self._receipts: dict[str, dict[str, Any]] = {}
        # Holder copies: every Disclosure, the action salt included, so they
        # leave the desk only through `proof_receipt`.
        self._proofs: dict[str, dict[str, Any]] = {}
        self._seq = 0
        self._intents: dict[str, _Intent] = {}
        self._intent_hashes: set[str] = set()
        # HTTP routes and the MCP session run on different threads.
        self._lock = threading.Lock()

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
        summary = pay_summary(
            str(intent.amount_cents),
            intent.currency,
            intent.recipient,
            intent.reference,
            self._source,
        )
        with self._lock:
            view = self._record_intent(intent, signature, summary)
            self._line("intent", view, summary)
            return view

    def intent_receipt(self, intent_id: str) -> dict[str, Any]:
        """Agent view of a recorded intent: fields and references only.

        Args:
            intent_id: Intent to read.

        Returns:
            Status (``signed`` or ``paid``), ids, hash, summary, the four
            fields, the statement's reference and the payment id; an unknown
            view when no such intent exists.
        """
        with self._lock:
            found = self._intents.get(intent_id)
            if found is None:
                return {"status": "unknown", "intent_id": intent_id}
            i = found.intent
            return {
                "status": "signed" if found.payment_id is None else "paid",
                "intent_id": intent_id,
                "intent_hash": found.hash,
                "summary": pay_summary(
                    str(i.amount_cents),
                    i.currency,
                    i.recipient,
                    i.reference,
                    self._source,
                ),
                "amount_cents": i.amount_cents,
                "currency": i.currency,
                "recipient": i.recipient,
                "reference": i.reference,
                "evidence_ref": found.funds_ref,
                "payment_id": found.payment_id,
            }

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
        intent that already paid, is denied without a gate run; the denial is
        still appended to the registry and sealed.

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
            return (
                _unknown(quote_id) if record is None else self._view(quote_id, record)
            )

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
        self._intents[intent_id] = _Intent(
            intent, digest, funds_ref, opaque_intent_ref(intent, signature)
        )
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

    def _refuse(self, quote_id: str, record: _Quote, reason: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "denied",
            "quote_id": quote_id,
            "reason": reason,
            "payment_id": None,
        }
        record.status = "denied"
        record.result = result
        self._append("denial", _result_body(result))
        self._emit("confirm", result, record.consent)
        return dict(result)

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
            salt=self._action_salts(),
            reasoning_commitment=reasoning_commitment(()),
            revocation_index=record.number % _REVOCATION_BITS,
            consent=c,
            holder_keys=self._holders,
            consents=self._ledger,
        )
        outcome = run_governed(request, self.bank, self._verifier)
        paid = outcome.reason == "ok: executed" and outcome.payment is not None
        payment_id = outcome.payment.payment_id if paid and outcome.payment else None
        result: dict[str, Any] = {
            "status": "confirmed" if paid else "denied",
            "quote_id": quote_id,
            "reason": outcome.reason,
            "payment_id": payment_id,
        }
        record.status = result["status"]
        record.result = result
        if payment_id is not None:
            self._receipts[payment_id] = result
            if bound is not None:
                bound.payment_id = payment_id
        body = _result_body(result)
        kind = "execution" if paid else "denial"
        seq, seal = self._append(kind, body)
        proof = self.registry.prove(seq)
        if (
            payment_id is not None
            and outcome.certificate
            and outcome.action
            and outcome.salt
        ):
            # The bank already paid: a receipt that cannot be built must not
            # turn the confirm into an error. The payment simply has none.
            try:
                self._proofs[payment_id] = proof_receipt(
                    payment_id,
                    outcome.certificate,
                    outcome.action,
                    DESK_POLICY,
                    c,
                    next(k for k in self._holders if verify_signature(c, (k,))),
                    LogEntry(seq, kind, body),
                    proof,
                    seal,
                    self._gate_key,
                    self._salts,
                    action_salt=outcome.salt,
                )
            except Exception as exc:
                # Only the type: a message could carry consent fields or keys.
                _log.error(
                    "receipt not built for %s (%s)", payment_id, type(exc).__name__
                )
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
