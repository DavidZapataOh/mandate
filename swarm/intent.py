"""Draft a payment intent from a transcript and resolve it against the payee book.

The model only names the payee and invoice as spoken. The account and the
exact open invoice come from the holder's payee book, never from the model.
"""

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from gate.policy import Intent
from swarm.agent import Responder
from swarm.meta_client import Item, MetaTrace

INTENT_FORMAT: Item = {
    "type": "json_schema",
    "name": "payment_intent",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "payee_name": {"type": "string"},
            "amount_cents": {"type": "integer"},
            "currency": {"type": "string"},
            "reference": {"type": "string"},
        },
        "required": ["payee_name", "amount_cents", "currency", "reference"],
        "additionalProperties": False,
    },
}
INTENT_INSTRUCTIONS = (
    "Extract the payment the account holder asked for. Amounts are integer cents. "
    "Copy the payee name and invoice reference as spoken."
)
_FIELDS = frozenset({"payee_name", "amount_cents", "currency", "reference"})


class IntentError(ValueError):
    """The drafted intent is unusable or does not match the payee book."""


def _norm(s: str) -> str:
    return re.sub(r"[^0-9a-z]", "", s.lower())


@dataclass(frozen=True)
class PayeeBook:
    """The holder's payees: normalized name to (account, open invoices).

    Args:
        entries: Payee key (stripped, lowercase) to account and open invoices.
    """

    entries: Mapping[str, tuple[str, tuple[str, ...]]]

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "PayeeBook":
        """Build a book from {name: {"account": ..., "open_invoices": [...]}}.

        Raises:
            IntentError: On a malformed entry or two names that normalize to
                the same key.
        """
        if not isinstance(raw, dict):
            raise IntentError("payee book: malformed")
        entries: dict[str, tuple[str, tuple[str, ...]]] = {}
        for name, v in raw.items():
            if not isinstance(name, str) or not isinstance(v, dict):
                raise IntentError("payee book: malformed")
            account, invoices = v.get("account"), v.get("open_invoices")
            if (
                not isinstance(account, str)
                or not account
                or not isinstance(invoices, list)
                or not all(isinstance(i, str) and i for i in invoices)
            ):
                raise IntentError("payee book: malformed")
            key = name.strip().lower()
            if key in entries:
                raise IntentError(f"payee book: duplicate payee {key}")
            entries[key] = (account, tuple(invoices))
        return cls(MappingProxyType(entries))

    def keywords(self) -> tuple[str, ...]:
        """Words worth biasing recognition toward: payees, then open invoices."""
        invoices = (i for _, open_ones in self.entries.values() for i in open_ones)
        return (*self.entries, *invoices)

    def resolve(self, payee_name: str, reference: str) -> tuple[str, str]:
        """Resolve a spoken payee and reference.

        Returns:
            (account, canonical open invoice).

        Raises:
            IntentError: When the payee is unknown or the reference does not
                match exactly one open invoice.
        """
        key = payee_name.strip().lower()
        if key not in self.entries:
            raise IntentError(f"payee not in book: {key}")
        account, invoices = self.entries[key]
        wanted = _norm(reference)
        matches = [i for i in invoices if wanted and _norm(i) == wanted]
        if len(matches) != 1:
            raise IntentError(f"reference not an open invoice: {reference}")
        return account, matches[0]


def draft_intent(
    meta: Responder,
    transcript: str,
    book: PayeeBook,
    model: str = "muse-spark-1.3",
) -> tuple[Intent, MetaTrace]:
    """Draft a structured intent from speech text and resolve it via the book.

    Raises:
        IntentError: On a blank transcript, a malformed draft, an unknown
            payee, or a reference that is not an open invoice.
    """
    if not transcript.strip():
        raise IntentError("empty transcript")
    resp = meta.respond(
        model,
        transcript,
        instructions=INTENT_INSTRUCTIONS,
        effort="low",
        text_format=INTENT_FORMAT,
    )
    try:
        draft = json.loads(resp.text)
    except ValueError:
        raise IntentError("draft: malformed") from None
    if not isinstance(draft, dict) or set(draft) != _FIELDS:
        raise IntentError("draft: malformed")
    amount = draft["amount_cents"]
    if type(amount) is not int or amount <= 0:
        raise IntentError("draft: amount_cents must be a positive integer")
    for field in ("payee_name", "currency", "reference"):
        value = draft[field]
        if not isinstance(value, str) or not value.strip():
            raise IntentError(f"draft: {field} must be a non-empty string")
    account, invoice = book.resolve(draft["payee_name"], draft["reference"])
    return Intent(amount, draft["currency"], account, invoice), resp.trace


def intent_bytes(intent: Intent) -> bytes:
    """Canonical bytes the holder signs (pinned format).

    Raises:
        IntentError: If the amount is not a positive int or a text field is
            not a non-empty string.
    """
    if (
        type(intent.amount_cents) is not int
        or intent.amount_cents <= 0
        or not all(
            isinstance(f, str) and f
            for f in (intent.currency, intent.recipient, intent.reference)
        )
    ):
        raise IntentError("intent: malformed")
    body = json.dumps(
        {
            "amount_cents": intent.amount_cents,
            "currency": intent.currency,
            "recipient": intent.recipient,
            "reference": intent.reference,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return b"intent/v1:" + body.encode("ascii")


def intent_hash(intent: Intent) -> str:
    """Hex sha256 of the canonical intent bytes."""
    return hashlib.sha256(intent_bytes(intent)).hexdigest()


def sign_intent(private_key: bytes, intent: Intent) -> bytes:
    """Sign the exact intent bytes with the holder's Ed25519 key."""
    return Ed25519PrivateKey.from_private_bytes(private_key).sign(intent_bytes(intent))


def confirmed_intent(public_key: bytes, intent: Intent, signature: bytes) -> Intent:
    """Return the intent only if the holder's signature covers its exact bytes.

    Limitation: the gate does not yet verify this holder signature, bind the
    debit account to it, or consume an intent after use. Callers must pass
    only intents confirmed here.

    Raises:
        IntentError: "intent: malformed" for a malformed intent; otherwise
            any verification failure, including malformed keys or signatures.
    """
    payload = intent_bytes(intent)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (InvalidSignature, ValueError, TypeError):
        raise IntentError("bad-signature: intent not confirmed") from None
    return intent
