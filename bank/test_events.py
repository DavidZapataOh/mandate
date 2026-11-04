import logging

import httpx
import pytest

from bank.api import RailError
from bank.conftest import SENTINEL_KEY, Cassette, event_body, events_page
from bank.events import (
    CATEGORIES,
    CURSOR_KEY,
    EVENT_TTL_S,
    MAX_PAGES,
    PAGE_LIMIT,
    SEEN_KIND,
    SUMMARIES,
    BankEvent,
    BankEvents,
)
from gate.state import StateStore

SINCE = "2026-11-04T08:00:00Z"
NOW = 1793782800
QUERY = {
    "category.in": (
        "account_transfer.created,account_transfer.updated,"
        "ach_transfer.created,ach_transfer.updated,"
        "inbound_ach_transfer.created,inbound_ach_transfer.updated,"
        "card_payment.created,card_payment.updated,"
        "real_time_decision.card_authorization_requested"
    ),
    "created_at.on_or_after": "2026-11-04T08:00:00Z",
    "limit": "100",
    "order_by.field": "created_at",
    "order_by.direction": "ascending",
}


def _feed(state, *answers):
    cassette = Cassette(*answers)
    return BankEvents(cassette.client(), state, SINCE, lambda: NOW), cassette


def _ids(events):
    return [e.event_id for e in events]


def test_poll_asks_oldest_first_for_the_banks_categories(state_store):
    feed, cassette = _feed(state_store, events_page(next_cursor="c1"))
    assert feed.poll([].append) == 0
    request = cassette.requests[0]
    assert (request.method, request.url.path) == ("GET", "/events")
    assert dict(request.url.params) == QUERY
    assert state_store.get(CURSOR_KEY) == "c1"


def test_an_event_becomes_one_bank_event(state_store):
    transfer = "sandbox_account_transfer_tts2u0bmjgmgyp08br4d"
    feed, _ = _feed(state_store, events_page(event_body(1, object_id=transfer)))
    shown = []
    assert feed.poll(shown.append) == 1
    assert shown == [
        BankEvent(
            "sandbox_event_000001",
            "account_transfer.created",
            "account_transfer",
            "sandbox_account_transfer_tts2u0bmjgmgyp08br4d",
            "2026-11-04T08:58:56Z",
            "Account transfer created",
        )
    ]


def test_every_category_has_its_summary():
    assert dict(SUMMARIES) == {
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
    assert tuple(SUMMARIES) == CATEGORIES


def test_events_are_committed_before_they_are_published(state_store):
    feed, _ = _feed(state_store, events_page(event_body(1), next_cursor="c1"))
    other = StateStore(state_store.path)
    states = []

    def publish(event):
        cursor = other.get(CURSOR_KEY)
        states.append((cursor, other.used(SEEN_KIND, event.event_id)))

    feed.poll(publish)
    other.close()
    assert states == [("c1", True)]


def test_a_publish_that_fails_mid_page_loses_the_rest_of_that_page(state_store):
    page = events_page(event_body(1), event_body(2), event_body(3))
    feed, _ = _feed(state_store, page, events_page(event_body(2), event_body(3)))
    shown = []

    def publish(event):
        if event.event_id == "sandbox_event_000002":
            raise RuntimeError("hub gone")
        shown.append(event)

    with pytest.raises(RuntimeError, match="hub gone"):
        feed.poll(publish)
    other = StateStore(state_store.path)
    assert other.get(CURSOR_KEY) == "c1"
    assert all(other.used(SEEN_KIND, f"sandbox_event_{n:06d}") for n in (1, 2, 3))
    other.close()
    assert feed.poll(shown.append) == 0
    assert _ids(shown) == ["sandbox_event_000001"]


def test_pages_before_a_failure_stay_committed_and_published(state_store):
    full = [event_body(n) for n in range(1, PAGE_LIMIT + 1)]
    feed, _ = _feed(
        state_store,
        events_page(*full, next_cursor="c1"),
        httpx.ReadTimeout("slow bank"),
    )
    shown = []
    with pytest.raises(RailError, match="bank: unavailable"):
        feed.poll(shown.append)
    assert len(shown) == PAGE_LIMIT
    assert state_store.get(CURSOR_KEY) == "c1"


def test_an_event_time_out_of_range_is_refused_not_wedged(state_store):
    bad = event_body(1, created_at="9999-12-31T23:59:59-05:00")
    feed, _ = _feed(
        state_store,
        events_page(bad, event_body(2), next_cursor="c1"),
        events_page(next_cursor="c2"),
    )
    shown = []
    assert feed.poll(shown.append) == 1
    assert (_ids(shown), feed.refused, feed.skipped) == (
        ["sandbox_event_000002"],
        1,
        0,
    )
    assert state_store.used(SEEN_KIND, "sandbox_event_000001")
    assert state_store.get(CURSOR_KEY) == "c1"
    assert feed.poll(shown.append) == 0
    assert state_store.get(CURSOR_KEY) == "c2"


def test_a_failed_commit_counts_nothing(state_store, monkeypatch):
    other = event_body(1, category="account.created")
    feed, _ = _feed(state_store, events_page(other, next_cursor="c1"))

    def broken_put(name, value):
        raise OSError("disk full")

    monkeypatch.setattr(state_store, "put", broken_put)
    with pytest.raises(OSError, match="disk full"):
        feed.poll([].append)
    assert feed.skipped == 0
    assert not state_store.used(SEEN_KIND, "sandbox_event_000001")


@pytest.mark.parametrize(
    "answer",
    [
        (401, {"type": "invalid_api_key_error", "status": 401}),
        httpx.ConnectError("bank down"),
        httpx.ReadTimeout("slow bank"),
    ],
)
def test_the_key_never_reaches_an_error_or_a_log(state_store, caplog, answer):
    caplog.set_level(logging.DEBUG)
    feed, _ = _feed(state_store, answer)
    with pytest.raises(RailError) as raised:
        feed.poll([].append)
    texts = [caplog.text]
    error: BaseException | None = raised.value
    while error is not None:
        texts += [str(error), repr(error)]
        error = error.__cause__ or error.__context__
    assert all(SENTINEL_KEY not in text for text in texts)


def test_no_duplicates_and_no_gaps_across_a_restart(tmp_path):
    path = tmp_path / "state" / "state.db"
    shown = []
    first = StateStore(path)
    page = events_page(event_body(1), event_body(2), next_cursor="c1")
    feed, _ = _feed(first, page)
    feed.poll(shown.append)
    first.close()
    again = StateStore(path)
    page = events_page(event_body(2), event_body(3), next_cursor="c2")
    feed, cassette = _feed(again, page)
    feed.poll(shown.append)
    assert _ids(shown) == [
        "sandbox_event_000001",
        "sandbox_event_000002",
        "sandbox_event_000003",
    ]
    assert cassette.requests[0].url.params["cursor"] == "c1"
    assert cassette.requests[0].url.params["created_at.on_or_after"] == SINCE
    assert again.get(CURSOR_KEY) == "c2"
    again.close()


def test_a_failed_poll_moves_no_cursor(state_store):
    feed, cassette = _feed(
        state_store,
        events_page(event_body(1), next_cursor="c1"),
        httpx.ConnectError("bank down"),
        events_page(event_body(2), next_cursor="c2"),
    )
    shown = []
    feed.poll(shown.append)
    with pytest.raises(RailError, match="bank: unavailable"):
        feed.poll(shown.append)
    assert state_store.get(CURSOR_KEY) == "c1"
    feed.poll(shown.append)
    assert _ids(shown) == ["sandbox_event_000001", "sandbox_event_000002"]
    cursors = [r.url.params.get("cursor") for r in cassette.requests]
    assert cursors == [None, "c1", "c1"]


def test_a_full_page_is_followed_by_the_next(state_store):
    full = [event_body(n) for n in range(1, PAGE_LIMIT + 1)]
    feed, cassette = _feed(
        state_store,
        events_page(*full, next_cursor="c1"),
        events_page(event_body(101), next_cursor="c2"),
    )
    assert feed.poll([].append) == 101
    assert len(cassette.requests) == 2
    assert state_store.get(CURSOR_KEY) == "c2"


def test_a_round_reads_at_most_ten_pages(state_store):
    pages = [
        events_page(
            *[event_body(p * PAGE_LIMIT + n) for n in range(1, PAGE_LIMIT + 1)],
            next_cursor=f"c{p + 1}",
        )
        for p in range(MAX_PAGES + 1)
    ]
    feed, cassette = _feed(state_store, *pages)
    assert feed.poll([].append) == 1000
    assert len(cassette.requests) == 10
    assert state_store.get(CURSOR_KEY) == "c10"


def test_other_categories_are_skipped_once(state_store):
    other = event_body(1, category="account.created")
    feed, _ = _feed(
        state_store,
        events_page(other, next_cursor="c1"),
        events_page(other, next_cursor="c2"),
    )
    shown = []
    feed.poll(shown.append)
    feed.poll(shown.append)
    assert (shown, feed.skipped) == ([], 1)
    assert state_store.get(CURSOR_KEY) == "c2"


@pytest.mark.parametrize(
    "answer",
    [
        (200, {"data": "x", "next_cursor": "c1"}),
        events_page(dict(event_body(1), id=7)),
        events_page(dict(event_body(1), created_at="soon")),
        events_page(dict(event_body(1), created_at="2026-11-04T08:58:56")),
        events_page(event_body(1), next_cursor=None),
        events_page(event_body(1), next_cursor=""),
        events_page(dict(event_body(1), id="")),
        events_page(dict(event_body(1), associated_object_id="")),
        events_page(dict(event_body(1), associated_object_type="")),
        events_page(dict(event_body(1), category="")),
        httpx.ReadTimeout("slow bank"),
        (401, {"type": "invalid_api_key_error", "status": 401}),
        (500, {"type": "internal_server_error", "status": 500}),
        httpx.Response(302, headers={"location": "https://evil.example/events"}),
    ],
)
def test_an_unusable_answer_is_unavailable_and_moves_nothing(state_store, answer):
    feed, _ = _feed(state_store, answer)
    shown = []
    with pytest.raises(RailError, match="bank: unavailable"):
        feed.poll(shown.append)
    assert (shown, state_store.get(CURSOR_KEY)) == ([], None)
    assert not state_store.used(SEEN_KIND, "sandbox_event_000001")


@pytest.mark.parametrize(
    "created_at", ["2026-11-04T09:58:56+01:00", "2026-11-04T08:58:56.123Z"]
)
def test_bank_times_are_utc_whole_seconds(state_store, created_at):
    page = events_page(event_body(1, created_at=created_at))
    feed, _ = _feed(state_store, page)
    shown = []
    feed.poll(shown.append)
    assert shown[0].created_at == "2026-11-04T08:58:56Z"


def test_seen_ids_last_as_long_as_the_bank_lists_events(state_store):
    feed, _ = _feed(state_store, events_page(event_body(1)))
    feed.poll([].append)
    state_store.prune(NOW + EVENT_TTL_S)
    assert state_store.used(SEEN_KIND, "sandbox_event_000001")
    state_store.prune(NOW + EVENT_TTL_S + 1)
    assert not state_store.used(SEEN_KIND, "sandbox_event_000001")
    assert EVENT_TTL_S == 31 * 86_400


def test_an_empty_page_without_a_cursor_is_caught_up(state_store):
    feed, cassette = _feed(
        state_store,
        events_page(next_cursor=None),
        events_page(event_body(1), next_cursor="c1"),
        events_page(next_cursor=None),
        events_page(next_cursor="c2"),
    )
    shown = []
    assert feed.poll(shown.append) == 0
    assert state_store.get(CURSOR_KEY) is None
    assert feed.poll(shown.append) == 1
    assert feed.poll(shown.append) == 0
    assert state_store.get(CURSOR_KEY) == "c1"
    assert feed.poll(shown.append) == 0
    assert state_store.get(CURSOR_KEY) == "c2"
    cursors = [r.url.params.get("cursor") for r in cassette.requests]
    assert cursors == [None, None, "c1", "c1"]
    assert _ids(shown) == ["sandbox_event_000001"]
