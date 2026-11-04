"""The bank's own events, read oldest first from a stored cursor.

Increase recommends continuously polling List Events when every event must
be received, and webhooks need a public HTTPS address; so the feed polls.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, TypeGuard, cast

from increase import Increase, Omit, omit
from increase.types import Event, event_list_params

from bank.api import RailError

if TYPE_CHECKING:
    from gate.state import StateStore

SUMMARIES: Mapping[str, str] = MappingProxyType(
    {
        "account_transfer.created": "Account transfer created",
        "account_transfer.updated": "Account transfer updated",
        "ach_transfer.created": "ACH transfer created",
        "ach_transfer.updated": "ACH transfer updated",
        "inbound_ach_transfer.created": "Inbound ACH transfer created",
        "inbound_ach_transfer.updated": "Inbound ACH transfer updated",
        "card_payment.created": "Card payment created",
        "card_payment.updated": "Card payment updated",
        "real_time_decision.card_authorization_requested": (
            "Card authorization requested"
        ),
    }
)
CATEGORIES: tuple[str, ...] = tuple(SUMMARIES)
PAGE_LIMIT = 100
MAX_PAGES = 10
# One day past the 30 days Increase lists an event for.
EVENT_TTL_S = 31 * 86_400
CURSOR_KEY = "bank_events_cursor"
SEEN_KIND = "bank_event"

_UNAVAILABLE = "bank: unavailable"
# The SDK types each category as a literal; CATEGORIES are all among them.
_FILTER = cast(event_list_params.Category, {"in": list(CATEGORIES)})


@dataclass(frozen=True)
class BankEvent:
    """One event the bank reported.

    Args:
        event_id: Increase event id.
        category: Event category, one of ``CATEGORIES``.
        object_type: Type of the object the event is about.
        object_id: Id of the object the event is about.
        created_at: Event time, UTC, whole seconds, ``YYYY-MM-DDTHH:MM:SSZ``.
        summary: The category in words.
    """

    event_id: str
    category: str
    object_type: str
    object_id: str
    created_at: str
    summary: str


def _checked(page: Any) -> tuple[list[Event], str | None]:
    data = getattr(page, "data", None)
    cursor = getattr(page, "next_cursor", None)
    if not isinstance(data, list):
        raise RailError(_UNAVAILABLE)
    # The sandbox answers a caught-up poll with no events and no cursor.
    if data == [] and cursor is None:
        return data, None
    if not _text(cursor):
        raise RailError(_UNAVAILABLE)
    for item in data:
        texts = (
            getattr(item, "id", None),
            getattr(item, "category", None),
            getattr(item, "associated_object_type", None),
            getattr(item, "associated_object_id", None),
        )
        created = getattr(item, "created_at", None)
        if (
            not isinstance(item, Event)
            or not all(_text(text) for text in texts)
            or not isinstance(created, datetime)
            or created.utcoffset() is None
        ):
            raise RailError(_UNAVAILABLE)
    return data, cursor


def _text(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and bool(value)


def _bank_event(event: Event) -> BankEvent | None:
    try:
        created_at = event.created_at.astimezone(UTC)
    except OverflowError:
        # A time past year 9999 in UTC: refusing the page would retry it
        # forever, so the event is spent and refused instead.
        return None
    return BankEvent(
        event.id,
        event.category,
        event.associated_object_type,
        event.associated_object_id,
        created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        SUMMARIES[event.category],
    )


class BankEvents:
    """Reads the bank's events of ``CATEGORIES``, each published at most once.

    Per page, the new event ids and the next cursor commit in one transaction
    before the page's events are published. A restart resumes at the stored
    cursor and never publishes an event twice; only a process that dies
    between the commit and the publish loses events, and it loses its
    published lines with them.

    Args:
        client: Increase client pinned to the sandbox.
        state: Durable store holding the cursor and the seen ids.
        since: ISO time the first poll starts at; re-sent with every poll.
        clock: Current Unix time in seconds.

    Attributes:
        skipped: New events of other categories, spent and never published.
        refused: New events whose time cannot be shown in UTC, spent and
            never published.
    """

    def __init__(
        self,
        client: Increase,
        state: "StateStore",
        since: str,
        clock: Callable[[], int],
    ) -> None:
        self._client = client
        self._state = state
        self._since = since
        self._clock = clock
        self.skipped = 0
        self.refused = 0

    def poll(self, publish: Callable[[BankEvent], object]) -> int:
        """Read at most ``MAX_PAGES`` pages and publish their new events.

        Args:
            publish: Receives each new event, oldest first.

        Returns:
            How many events were published.

        Raises:
            RailError: ``bank: unavailable`` when the bank fails or answers
                with anything but a page of events; that page moves nothing,
                and pages read before it stay committed and published.
            Exception: Whatever ``publish`` raised. Its page is already
                committed, so the page's remaining events are never shown.
        """
        published = 0
        for _ in range(MAX_PAGES):
            events, cursor = self._page()
            if cursor is None:
                break
            fresh: list[BankEvent] = []
            skipped = refused = 0
            expires_at = self._clock() + EVENT_TTL_S
            with self._state.transaction():
                for event in events:
                    if not self._state.consume(SEEN_KIND, event.id, expires_at):
                        continue
                    if event.category not in SUMMARIES:
                        skipped += 1
                    elif (bank_event := _bank_event(event)) is None:
                        refused += 1
                    else:
                        fresh.append(bank_event)
                self._state.put(CURSOR_KEY, cursor)
            self.skipped += skipped
            self.refused += refused
            for bank_event in fresh:
                publish(bank_event)
            published += len(fresh)
            if len(events) < PAGE_LIMIT:
                break
        return published

    def _page(self) -> tuple[list[Event], str | None]:
        cursor = self._state.get(CURSOR_KEY)
        after: str | Omit = omit if cursor is None else cursor
        try:
            page = self._client.events.list(
                order_by={"field": "created_at", "direction": "ascending"},
                category=_FILTER,
                created_at={"on_or_after": self._since},
                limit=PAGE_LIMIT,
                cursor=after,
            )
        except Exception:
            raise RailError(_UNAVAILABLE) from None
        return _checked(page)
