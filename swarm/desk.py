"""Payment desk: quote, holder approval, gated confirm, receipt."""

import dataclasses
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from bank.api import Bank
from bank.verifier import Verifier
from gate.certs import public_key_of
from gate.consent import Consent, ConsentLedger, consent_bytes, verify_signature
from gate.events import DecisionEvent
from gate.policy import Intent, Policy, Rule
from gate.registry import Registry
from gate.shim import Mode, RawCall
from mandate.client import RunRequest, run_governed
from swarm.console_line import ConsoleLine, desk_line, forensic_of, pay_summary
from swarm.meta_client import reasoning_commitment

DESK_POLICY = Policy(
    "desk",
    1,
    (
        Rule(
            "pay-with-consent", "mcp:bank.pay", "transfer", "*", True, None, False, True
        ),
    ),
)
_KEY_LEN = 32
_REVOCATION_BITS = 1024
_T = TypeVar("_T")


@dataclass
class _Quote:
    number: int
    consent: Consent
    status: str = "quoted"
    result: dict[str, Any] | None = None


class PaymentDesk:
    """Holds quotes until the holder signs, then pays once through the gate.

    Args:
        source: Account every quote debits.
        bank: Ledger the confirmed payments execute against.
        verifier: Certificate verifier bound to the gate's public key.
        gate_key: Raw Ed25519 private key the gate signs certificates with.
        clock: Current unix time in seconds.
        nonces: Source of unique nonces for consents and certificates.
        quote_ttl_s: Seconds a quote stays approvable.
        publish: Receives one console line per desk step, under the desk lock,
            so line order is the desk's order.
    """

    def __init__(
        self,
        source: str,
        bank: Bank,
        verifier: Verifier,
        gate_key: bytes,
        clock: Callable[[], int],
        nonces: Callable[[], str],
        quote_ttl_s: int = 600,
        publish: Callable[[ConsoleLine], object] | None = None,
    ) -> None:
        self.bank = bank
        self.registry = Registry()
        self._source = source
        self._verifier = verifier
        self._gate_key = gate_key
        self._clock = clock
        self._nonces = nonces
        self._ttl = quote_ttl_s
        self._publish = publish
        self._gate_pub = public_key_of(gate_key)
        self._ledger = ConsentLedger()
        self._holders: tuple[bytes, ...] = ()
        self._quotes: dict[str, _Quote] = {}
        self._receipts: dict[str, dict[str, Any]] = {}
        self._seq = 0
        # HTTP routes and the MCP session run on different threads.
        self._lock = threading.Lock()

    @property
    def source(self) -> str:
        """Account every quote debits."""
        return self._source

    def guarded(self, work: Callable[[Bank, Verifier], _T]) -> _T:
        """Run ``work`` against the desk's bank and verifier under the desk lock.

        Args:
            work: Callable receiving the bank and the verifier.

        Returns:
            Whatever ``work`` returns.
        """
        with self._lock:
            return work(self.bank, self._verifier)

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

    def quote(
        self, recipient: str, amount_cents: int, currency: str, reference: str
    ) -> dict[str, Any]:
        """Open a quote the holder can approve.

        Args:
            recipient: Payee account.
            amount_cents: Amount in integer cents.
            currency: Currency code.
            reference: Payment reference.

        Returns:
            The quoted view, or a denied dict when a field is malformed.
        """
        with self._lock:
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
            record = _Quote(self._seq, consent)
            self._quotes[_quote_id(self._seq)] = record
            view = self._quoted_view(record)
            self._emit("quote", view, consent)
            return view

    def pending(self) -> list[dict[str, Any]]:
        """Quotes still awaiting approval, in id order."""
        with self._lock:
            return [
                self._quoted_view(q)
                for q in self._quotes.values()
                if q.status == "quoted"
            ]

    def approve(self, quote_id: str, signature: bytes) -> dict[str, Any]:
        """Record the holder's signature over a quote.

        Args:
            quote_id: Quote to approve.
            signature: Ed25519 signature over the quote's consent bytes.

        Returns:
            The approved view, the quote's current view when it is no longer
            open, an expired view past its deadline, or a denied dict for a
            bad signature (the quote stays open).
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
            signed = dataclasses.replace(record.consent, signature=signature)
            if not verify_signature(signed, self._holders):
                denied = {
                    "status": "denied",
                    "reason": "consent: bad signature",
                    "quote_id": quote_id,
                }
                self._emit("approve", denied, record.consent)
                return denied
            record.consent = signed
            record.status = "approved"
            view = self._view(quote_id, record)
            self._emit("approve", view, signed)
            return view

    def confirm(self, quote_id: str) -> dict[str, Any]:
        """Run the approved payment through the gate, at most once.

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
            if not self.registry.has_room():
                return {
                    "status": "denied",
                    "reason": "registry: full",
                    "quote_id": quote_id,
                }
            return self._execute(quote_id, record)

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

    def _execute(self, quote_id: str, record: _Quote) -> dict[str, Any]:
        c = record.consent
        now = self._clock()
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
                evidence_refs=(quote_id,),
                reversible=False,
            ),
            policy=DESK_POLICY,
            intent=Intent(c.amount_cents, c.currency, c.recipient, c.reference),
            private_key=self._gate_key,
            mode=Mode.ENFORCE,
            now=now,
            nonce=self._nonces(),
            timestamp=now,
            scope=f"mcp:bank.pay:transfer:{self._source}",
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
        body = json.dumps(
            {k: result[k] for k in ("payment_id", "quote_id", "reason", "status")},
            sort_keys=True,
            separators=(",", ":"),
        )
        seq = self.registry.append("execution" if paid else "denial", body)
        forensic = None
        if outcome.action is not None:
            forensic = forensic_of(
                outcome.action,
                DESK_POLICY,
                outcome.certificate,
                self._gate_pub,
                consent=c,
                proof=self.registry.prove(seq),
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
        if self._publish is None:
            return
        summary = pay_summary(
            str(consent.amount_cents),
            consent.currency,
            consent.recipient,
            consent.reference,
            consent.source,
        )
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
