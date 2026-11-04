"""The bank side of a card authorization: the webhook, the decision, the answer."""

import argparse
import datetime
import os
import secrets
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final

import httpx
from increase import (
    AuthenticationError,
    Increase,
    IncreaseError,
    PermissionDeniedError,
    RateLimitError,
)
from increase.types import RealTimeDecision
from increase.types.real_time_decision import (
    CardAuthorization as BankCardAuthorization,
)

from bank.api import Payment, PaymentRequest, RailError
from bank.credentials import BANK_KEY_ENV, take_bank_key, take_webhook_secret
from bank.increase import (
    DEMO_ACCOUNTS,
    PROVIDER,
    IncreaseRail,
    refusal,
    sandbox_client,
)
from bank.rail import CARD_DECISION, SANDBOX

CARD_CATEGORY: Final = "real_time_decision.card_authorization_requested"
# The bank's deadline for a card authorization, in seconds.
CARD_DEADLINE_S = 4.0
# No approve starts later than the deadline minus this.
CARD_SAFETY_S = 0.5
# Time kept free for the gate run before the safety margin: no confirm
# starts with less left, because the gate spends the holder's approval
# whatever the bank answers. A durable desk's whole confirm measures about
# 1 ms here, so this leaves wide headroom for a loaded host.
CARD_GATE_S = 0.25
# How long the one read that settles a lost approve answer may take.
CARD_SETTLE_TIMEOUT_S = 2.0
# The agent card's description at the bank.
AGENT_CARD = "mandate-agent-card"
DECLINE_REASON: Final = "transaction_never_allowed"
MAX_WEBHOOK_BODY = 16_384

UNSIGNED = "webhook: unsigned"
BAD_SIGNATURE = "webhook: bad signature"
NOT_A_CARD_AUTHORIZATION = "webhook: not a card authorization"

MALFORMED = "card: malformed decision"
NOT_A_PURCHASE = "card: not a purchase"
NOT_PENDING = "card: not pending"
DIFFERS = "card: authorization differs"
DEADLINE_PASSED = "card: deadline passed"
DECLINED_AT_BANK = "card: declined at the bank"
_UNKNOWN = "bank: outcome unknown"
_UNAVAILABLE = "bank: unavailable"
APPROVED = "approved"
_DECLINE_KEY = "mandate-decline-"
_CERT_KEY = "mandate-cert-"

_SIGNATURE_HEADERS = ("webhook-id", "webhook-timestamp", "webhook-signature")
NO_AGENT_CARD = "agent card missing: run mandate-bank-setup --card-webhook-url <url>\n"


class CardWebhookError(Exception):
    """A webhook that names no card decision; the message is the refusal reason."""


def webhook_decision_id(
    client: Increase, body: bytes, headers: Mapping[str, str], secret: str
) -> str:
    """Verify the bank's signed webhook and return the decision it names.

    Only the decision id is taken from the webhook; every field Mandate
    decides on is read from the bank afterwards.

    Args:
        client: Increase client whose ``events.unwrap`` verifies the signature.
        body: The raw request body, exactly as received.
        headers: The request headers, in any letter case.
        secret: The secret shared with the bank's event subscription.

    Returns:
        The real-time decision id of a card authorization request.

    Raises:
        CardWebhookError: If the webhook is unsigned, its signature does not
            verify (any failure counts), or it is not a card authorization.
    """
    lowered: dict[str, str] = {}
    for name, value in headers.items():
        key = name.lower()
        if key in _SIGNATURE_HEADERS and lowered.get(key, value) != value:
            # Two spellings of one header that disagree: neither is trusted.
            raise CardWebhookError(BAD_SIGNATURE)
        lowered[key] = value
    signed = {name: lowered.get(name, "") for name in _SIGNATURE_HEADERS}
    if not all(signed.values()):
        raise CardWebhookError(UNSIGNED)
    try:
        event = client.events.unwrap(
            body.decode("utf-8"), headers=signed, key=secret.encode("utf-8")
        )
    except Exception:
        # A malformed header or body raises ValueError or UnicodeDecodeError,
        # not the library's own error: every failure is unverified.
        raise CardWebhookError(BAD_SIGNATURE) from None
    decision = getattr(event, "associated_object_id", None)
    if (
        getattr(event, "category", None) != CARD_CATEGORY
        or getattr(event, "associated_object_type", None) != "real_time_decision"
        or not isinstance(decision, str)
        or CARD_DECISION.fullmatch(decision) is None
    ):
        raise CardWebhookError(NOT_A_CARD_AUTHORIZATION)
    return decision


@dataclass(frozen=True)
class CardAuthorization:
    """One pending card purchase, as the bank's decision reports it.

    Args:
        decision_id: The bank's real-time decision id.
        account_id: The bank account the card draws on.
        card_id: The card being charged.
        amount_cents: Settlement amount in integer cents.
        currency: Settlement currency.
        merchant: The merchant's acceptor id.
        descriptor: The merchant's descriptor.
        timeout_at: The bank's deadline for the answer, in unix seconds.
    """

    decision_id: str
    account_id: str
    card_id: str
    amount_cents: int
    currency: str
    merchant: str
    descriptor: str
    timeout_at: float


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(MALFORMED)
    return value


def read_authorization(decision: object) -> CardAuthorization:
    """Read a pending card purchase from the bank's real-time decision.

    The SDK does not validate the answer, so every field is checked here.
    A malformed decision is reported as such before anything else, and the
    status is checked last, so a malformed decision never reads as late.

    Args:
        decision: The decision as ``real_time_decisions.retrieve`` returned it.

    Returns:
        The authorization's fields.

    Raises:
        ValueError: ``card: malformed decision``, ``card: not a purchase`` or
            ``card: not pending``, in that order of precedence.
    """
    if not isinstance(decision, RealTimeDecision):
        raise ValueError(MALFORMED)
    decision_id = decision.id
    if not isinstance(decision_id, str) or CARD_DECISION.fullmatch(decision_id) is None:
        raise ValueError(MALFORMED)
    card = decision.card_authorization
    if not isinstance(card, BankCardAuthorization):
        raise ValueError(MALFORMED)
    amount: object = card.settlement_amount
    if type(amount) is not int or amount <= 0:
        raise ValueError(MALFORMED)
    timeout_at: object = decision.timeout_at
    if not isinstance(timeout_at, datetime.datetime) or timeout_at.utcoffset() is None:
        raise ValueError(MALFORMED)
    authorization = CardAuthorization(
        decision_id,
        _text(card.account_id),
        _text(card.card_id),
        amount,
        _text(card.settlement_currency),
        _text(card.merchant_acceptor_id),
        _text(card.merchant_descriptor),
        timeout_at.timestamp(),
    )
    if (
        decision.category != "card_authorization_requested"
        or card.direction != "settlement"
        or card.processing_category != "purchase"
    ):
        raise ValueError(NOT_A_PURCHASE)
    if decision.status != "pending":
        raise ValueError(NOT_PENDING)
    return authorization


def within_budget(total: float) -> httpx.Timeout:
    """Split a time budget over the phases of one call, so they sum to it.

    httpx bounds each phase on its own; a single number would let a call
    connect, write and read for that long each.

    Args:
        total: The whole call's budget, in seconds.

    Returns:
        A timeout whose four phases add up to ``total``.
    """
    return httpx.Timeout(
        connect=total * 0.25, write=total * 0.1, read=total * 0.55, pool=total * 0.1
    )


def _answered(answer: object, decision_id: str, decision: str) -> bool:
    """Tell whether the bank says this decision was answered with ``decision``."""
    return (
        isinstance(answer, RealTimeDecision)
        and answer.id == decision_id
        and answer.status == "responded"
        and getattr(answer.card_authorization, "decision", None) == decision
    )


class CardDecisionRail:
    """A bank rail for one card decision: executing it approves the purchase.

    The bank verifier calls ``execute`` last and once, so the approval is
    the certified payment. The whole approve call, every phase of it, ends
    by the deadline minus ``CARD_SAFETY_S``; a lost answer is settled by one
    read, never by a second approval or a client retry.

    Args:
        client: Increase client pinned to the sandbox.
        authorization: The pending purchase, as read from the bank.
        source: The account name the certificate pays from.
        account_id: The bank's id for that account.
        deadline: When the bank stops waiting, in unix seconds; the
            decision's own ``timeout_at`` caps it.
        clock: The current time in unix seconds.
        card_id: The agent card; an authorization on any other card differs.
    """

    def __init__(
        self,
        client: Increase,
        authorization: CardAuthorization,
        source: str,
        account_id: str,
        deadline: float,
        clock: Callable[[], float],
        *,
        card_id: str,
    ) -> None:
        # A resent approve could reach the bank after the deadline.
        self._client = client.with_options(max_retries=0)
        self._auth = authorization
        self._source = source
        self._account_id = account_id
        self._card_id = card_id
        # Never later than the bank's own deadline, whatever the caller passed.
        self._deadline = min(deadline, authorization.timeout_at)
        self._clock = clock

    @property
    def rail(self) -> str:
        """Always the sandbox label."""
        return SANDBOX

    def left(self) -> float:
        """Seconds until no approve may start any more (may be negative)."""
        return self._deadline - CARD_SAFETY_S - self._clock()

    @property
    def provider(self) -> str:
        """The bank that holds the card."""
        return PROVIDER

    def execute(
        self,
        request: PaymentRequest,
        action_hash: str,
        idempotency_key: str | None = None,
    ) -> Payment:
        """Approve the card purchase under the certificate's key, in time.

        Args:
            request: The certified payment; it must be this authorization.
            action_hash: Salted hash of the action the payment settles.
            idempotency_key: ``mandate-cert-<jti>``; required.

        Returns:
            The approved payment, whose id is the bank's decision id.

        Raises:
            ValueError: If the key is not a ``mandate-cert-`` certificate key.
            RailError: ``card: authorization differs`` or ``card: deadline
                passed`` before any bank call; ``bank: unavailable`` when the
                bank refused the key or the rate; ``card: deadline passed``,
                ``card: declined at the bank`` or ``bank: outcome unknown``
                when the approval's answer was lost and one read settles it.
        """
        if (
            idempotency_key is None
            or not idempotency_key.startswith(_CERT_KEY)
            or idempotency_key == _CERT_KEY
        ):
            raise ValueError("card decisions need a certificate key")
        auth = self._auth
        asked = (request.amount_cents, request.currency, request.to_acct)
        if asked != (auth.amount_cents, auth.currency, auth.merchant) or (
            request.from_acct,
            self._account_id,
            self._card_id,
        ) != (self._source, auth.account_id, auth.card_id):
            raise RailError(DIFFERS)
        budget = self.left()
        if budget <= 0:
            raise RailError(DEADLINE_PASSED)
        try:
            answer: object = self._client.real_time_decisions.action(
                auth.decision_id,
                card_authorization={"decision": "approve"},
                idempotency_key=idempotency_key,
                timeout=within_budget(budget),
            )
        except (AuthenticationError, PermissionDeniedError, RateLimitError) as exc:
            if refusal(exc):
                raise RailError(_UNAVAILABLE) from None
            answer = None
        except Exception:
            # No answer, or one the SDK could not read: the bank may still
            # have taken the approval.
            answer = None
        if not _answered(answer, auth.decision_id, "approve"):
            self._settle()
        return Payment(
            auth.decision_id,
            request.from_acct,
            request.to_acct,
            request.amount_cents,
            request.currency,
            request.ref,
            action_hash,
            rail=SANDBOX,
            provider=PROVIDER,
            status=APPROVED,
            idempotency_key=idempotency_key,
        )

    def _settle(self) -> None:
        """Read the decision once; return only if the bank holds it approved."""
        decision_id = self._auth.decision_id
        try:
            read: object = self._client.real_time_decisions.retrieve(
                decision_id, timeout=CARD_SETTLE_TIMEOUT_S
            )
        except Exception:
            raise RailError(_UNKNOWN) from None
        if _answered(read, decision_id, "approve"):
            return
        if not isinstance(read, RealTimeDecision) or read.id != decision_id:
            raise RailError(_UNKNOWN)
        if read.status == "timed_out":
            raise RailError(DEADLINE_PASSED)
        if _answered(read, decision_id, "decline"):
            raise RailError(DECLINED_AT_BANK)
        raise RailError(_UNKNOWN)

    def reconcile(
        self, request: PaymentRequest, action_hash: str, idempotency_key: str
    ) -> Payment | None:
        """Never look a card decision up as a transfer.

        Raises:
            RailError: Always ``bank: outcome unknown``.
        """
        raise RailError(_UNKNOWN)

    def get_balance(self, acct: str) -> int:
        """A card decision reports no balance.

        Raises:
            RailError: Always ``bank: unavailable``.
        """
        raise RailError(_UNAVAILABLE)


def decline(
    client: Increase,
    decision_id: str,
    deadline: float,
    clock: Callable[[], float],
) -> bool:
    """Decline a card decision under its own key, only before the deadline.

    Args:
        client: Increase client pinned to the sandbox.
        decision_id: The bank's real-time decision id.
        deadline: When the bank stops waiting, in unix seconds.
        clock: The current time in unix seconds.

    Returns:
        True when the bank answers that the decision was declined; False
        otherwise, including a late call (nothing is posted) and any error,
        which leave the bank's own default decline.
    """
    left = deadline - clock()
    if left <= 0:
        return False
    try:
        answer: object = client.with_options(max_retries=0).real_time_decisions.action(
            decision_id,
            card_authorization={
                "decision": "decline",
                "decline": {"reason": DECLINE_REASON},
            },
            idempotency_key=_DECLINE_KEY + decision_id,
            timeout=within_budget(left),
        )
    except Exception:
        return False
    return _answered(answer, decision_id, "decline")


def agent_card(client: Increase, account_id: str) -> str | None:
    """Find the agent card on an account.

    Args:
        client: Increase client pinned to the sandbox.
        account_id: The bank's id for the account the card draws on.

    Returns:
        The id of the first active card described as ``AGENT_CARD``, or None.
    """
    for found in client.cards.list(account_id=account_id):
        if found.status == "active" and found.description == AGENT_CARD:
            return found.id
    return None


def ensure_card(client: Increase, account_id: str, name: str) -> str:
    """Return the agent card on an account, opening one if there is none.

    The card is opened under a fixed idempotency key, so running it again
    opens nothing twice.

    Args:
        client: Increase client pinned to the sandbox.
        account_id: The bank's id for the account the card draws on.
        name: Mandate name of that account.

    Returns:
        The agent card's id.
    """
    found = agent_card(client, account_id)
    if found is not None:
        return found
    created = client.cards.create(
        account_id=account_id,
        description=AGENT_CARD,
        idempotency_key=f"mandate-setup-card-{name}",
    )
    return created.id


def _selects_card(subscription: object) -> bool:
    categories = getattr(subscription, "selected_event_categories", None) or ()
    return getattr(subscription, "status", None) == "active" and any(
        getattr(item, "event_category", None) == CARD_CATEGORY for item in categories
    )


def ensure_card_subscription(client: Increase, url: str, secret: str) -> None:
    """Point the one real-time card subscription at a URL.

    The bank lets one active subscription handle a real-time category, and
    a subscription's URL cannot change: every other one is deleted first,
    then one is created unless an active one already points at the URL.

    Args:
        client: Increase client pinned to the sandbox.
        url: The HTTPS URL the bank sends card authorizations to.
        secret: The secret the bank signs those webhooks with.
    """
    current = False
    for subscription in client.event_subscriptions.list():
        if not _selects_card(subscription):
            continue
        if subscription.url == url:
            current = True
        else:
            client.event_subscriptions.update(subscription.id, status="deleted")
    if not current:
        client.event_subscriptions.create(
            url=url,
            # The SDK and the API name the key event_category.
            selected_event_categories=[{"event_category": CARD_CATEGORY}],
            shared_secret=secret,
            idempotency_key=f"mandate-setup-rtd-{secrets.token_hex(8)}",
        )


def _charge_answer(answer: object) -> str | None:
    pending = getattr(answer, "pending_transaction", None)
    if isinstance(getattr(pending, "id", None), str):
        return f"approved ({pending.id})"  # type: ignore[union-attr]
    declined = getattr(answer, "declined_transaction", None)
    card_decline = getattr(getattr(declined, "source", None), "card_decline", None)
    reason = getattr(card_decline, "reason", None)
    if isinstance(reason, str):
        return f"declined ({reason})"
    return None


def charge_cli(argv: list[str] | None = None) -> None:
    """Entry point for ``mandate-card-charge``: the sandbox merchant stand-in.

    Charges the agent card through Increase's card authorization
    simulation, so the bank asks Mandate for its real-time decision.

    Args:
        argv: Command-line arguments; ``sys.argv[1:]`` when None.
    """
    parser = argparse.ArgumentParser(
        prog="mandate-card-charge",
        description=(
            "Charge the agent card as a sandbox merchant would "
            "(Increase card authorization simulation)."
        ),
    )
    parser.add_argument("--amount-cents", type=int, required=True)
    parser.add_argument("--merchant", default=DEMO_ACCOUNTS[1])
    parser.add_argument("--descriptor", default="ACME 991")
    args = parser.parse_args(argv)
    key = take_bank_key(os.environ)
    # This process never needs the webhook secret; no child may inherit it.
    take_webhook_secret(os.environ)
    if key is None:
        parser.exit(2, f"bank rail unavailable: set {BANK_KEY_ENV}\n")
    client = sandbox_client(key)
    payer = DEMO_ACCOUNTS[0]
    try:
        rail = IncreaseRail.connect(client)
        card_id = (
            agent_card(client, rail.account_id(payer)) if rail.holds((payer,)) else None
        )
        if card_id is None:
            parser.exit(2, NO_AGENT_CARD)
        answer = client.simulations.card_authorizations.create(
            amount=args.amount_cents,
            card_id=card_id,
            merchant_acceptor_id=args.merchant,
            merchant_descriptor=args.descriptor,
            idempotency_key=f"mandate-charge-{secrets.token_hex(8)}",
        )
    except (AuthenticationError, PermissionDeniedError):
        parser.exit(2, "bank rail unavailable: the sandbox refused the key\n")
    except IncreaseError:
        parser.exit(2, "bank rail unavailable: the sandbox is unreachable\n")
    printed = _charge_answer(answer)
    if printed is None:
        sys.stderr.write("card authorization answer unreadable\n")
        raise SystemExit(1)
    print(f"Card authorization at {args.merchant}: {printed}", flush=True)
