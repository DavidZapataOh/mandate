import pytest

from gate.certs import public_key_of
from gate.registry import EMPTY_ROOT
from swarm.hub import EventHub
from swarm.provenance import provenance
from swarm.server import build_server
from swarm.test_server import FOREIGN, PAIR, _asgi

ROOT1 = "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87"
POLICIES = [
    {
        "policy_id": "desk",
        "version": 1,
        "rules": [
            {
                "rule_id": "pay-with-consent",
                "actor": "mcp:bank.pay",
                "operation": "transfer",
                "target": "*",
                "amount_exact": True,
                "amount_lte_cents": None,
                "approval_required": False,
                "consent_required": True,
            }
        ],
    },
    {
        "policy_id": "payments",
        "version": 1,
        "rules": [
            {
                "rule_id": "pay-intent",
                "actor": "muse:bank.pay",
                "operation": "transfer",
                "target": "*",
                "amount_exact": True,
                "amount_lte_cents": None,
                "approval_required": False,
                "consent_required": False,
            }
        ],
    },
    {
        "policy_id": "nimbus",
        "version": 1,
        "rules": [
            {
                "rule_id": "release-api-v2",
                "actor": "muse-code:nimbus",
                "operation": "deploy",
                "target": "artifact:api-v2",
                "amount_exact": False,
                "amount_lte_cents": None,
                "approval_required": False,
                "consent_required": False,
            },
            {
                "rule_id": "migrate-0042",
                "actor": "muse-code:nimbus",
                "operation": "migrate",
                "target": "artifact:migration-0042",
                "amount_exact": False,
                "amount_lte_cents": None,
                "approval_required": False,
                "consent_required": False,
            },
        ],
    },
]


def _paid(make_desk, sign_quote, hub):
    desk, holder = make_desk(publish=hub.publish)
    q = desk.quote("acme-991", 20000, "USD", "A-991")
    desk.approve("q:000001", sign_quote(holder, q))
    desk.confirm("q:000001")
    return desk


def test_provenance_of_an_empty_console(make_desk):
    desk, _ = make_desk()
    hub = EventHub()
    assert provenance(hub, desk) == {
        "epoch": hub.epoch,
        "window": {"first_seq": 0, "last_seq": 0, "retained": 0},
        "registry": {"root": EMPTY_ROOT, "leaves": 0},
        "policies": POLICIES,
        "bank": None,
        "holders": 1,
    }


def test_provenance_after_a_paid_quote(make_desk, sign_quote):
    hub = EventHub()
    desk = _paid(make_desk, sign_quote, hub)
    found = provenance(hub, desk)
    assert found["window"] == {"first_seq": 1, "last_seq": 3, "retained": 3}
    assert found["registry"] == {"root": ROOT1, "leaves": 1}


def test_provenance_window_after_eviction(make_desk, sign_quote):
    hub = EventHub(max_lines=2)
    desk = _paid(make_desk, sign_quote, hub)
    assert provenance(hub, desk)["window"] == {
        "first_seq": 2,
        "last_seq": 3,
        "retained": 2,
    }


@pytest.mark.anyio
async def test_provenance_route(make_desk, sign_quote):
    hub = EventHub()
    desk = _paid(make_desk, sign_quote, hub)
    app = build_server(desk, PAIR, hub=hub).streamable_http_app()
    async with _asgi(app) as http:
        resp = await http.get("/api/provenance")
        foreign = await http.get("/api/provenance", headers=FOREIGN)
    assert resp.headers["cache-control"] == "no-store"
    assert resp.json() == {
        "epoch": hub.epoch,
        "window": {"first_seq": 1, "last_seq": 3, "retained": 3},
        "registry": {"root": ROOT1, "leaves": 1},
        "policies": POLICIES,
        "bank": None,
        "holders": 1,
    }
    assert (foreign.status_code, foreign.json()) == (400, {"error": "bad request"})


@pytest.mark.anyio
async def test_provenance_route_absent_without_hub(make_desk):
    desk, _ = make_desk()
    async with _asgi(build_server(desk, PAIR).streamable_http_app()) as http:
        resp = await http.get("/api/provenance")
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_provenance_carries_the_latest_reconciliation(make_desk, state_store):
    hub = EventHub()
    desk, _ = make_desk(publish=hub.publish, state=state_store)
    desk.reconcile()
    async with _asgi(build_server(desk, PAIR, hub=hub).streamable_http_app()) as http:
        body = (await http.get("/api/provenance")).json()
    assert (body["bank"]["rail"], body["bank"]["transfers"]) == ("simulated", 0)


def test_provenance_counts_paired_holders(make_desk):
    desk, _ = make_desk()
    hub = EventHub()
    holder_id = desk.register_holder(public_key_of(b"\x03" * 32))
    assert provenance(hub, desk)["holders"] == 2
    desk.unpair_holder(holder_id)
    assert provenance(hub, desk)["holders"] == 1
