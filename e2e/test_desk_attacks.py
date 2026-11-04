import base64
import json
from collections.abc import Iterator

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from e2e.attack_world import QUOTE, Console, approval_body, b64, unsigned
from gate.certs import generate_keypair
from gate.consent import HolderApproval, sign_approval
from swarm.holders import unpair_bytes
from swarm.server import PAIRING_TTL_S, build_server

ZERO = HolderApproval(b"\x00" * 64, b"\x00" * 32, b"\x00" * 64)
SEED = b"\x81" * 32
JSON = {"content-type": "application/json"}
FOREIGN = {"host": "evil.example:8765"}
PAID = {
    "status": "confirmed",
    "quote_id": "q:000001",
    "reason": "ok: executed",
    "payment_id": "pay:000001",
}
# Small-order Ed25519 points: under them a signature needs no secret.
SMALL_ORDER = [
    bytes.fromhex("01" + "00" * 31),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
]
LOCAL_ONLY = (403, {"error": "holder copy is local only"})
BAD = (400, {"error": "bad request"})


@pytest.fixture
def console(tmp_path) -> Iterator[Console]:
    served = Console(tmp_path).start()
    try:
        yield served
    finally:
        served.stop()


def _denied(reason: str, quote_id: str) -> dict[str, str]:
    return {"status": "denied", "reason": reason, "quote_id": quote_id}


def _moved(console: Console) -> tuple[int, int]:
    """Transfers that left the desk's account, and how many are certified."""
    report = console.post("/api/reconcile", json={}).json()
    return report["transfers"], report["certified"]


def test_the_agent_cannot_confirm_what_the_holder_never_approved(console):
    quote = console.tool("quote_payment", QUOTE)
    confirmed = console.tool("confirm_payment", {"quote_id": quote["quote_id"]})
    assert (confirmed["status"], confirmed["quote_id"]) == ("quoted", "q:000001")
    assert console.get("/api/registry").json() == {"seal": None}
    assert _moved(console) == (0, 0)


def test_the_agent_cannot_approve_with_any_key_of_its_own(console):
    holder = console.pair()
    quote = console.tool("quote_payment", QUOTE)
    agent_key, _ = generate_keypair()
    forged = [
        console.post("/api/approve", json=approval_body("q:000001", ZERO)).json(),
        console.approve(quote, agent_key),
    ]
    assert forged == [_denied("consent: bad signature", "q:000001")] * 2
    assert console.tool("confirm_payment", {"quote_id": "q:000001"})["status"] == (
        "quoted"
    )
    assert console.approve(quote, holder)["status"] == "approved"


def test_an_approval_moves_to_no_other_quote(console):
    holder = console.pair()
    first = console.tool("quote_payment", QUOTE)
    console.tool("quote_payment", QUOTE)
    for_first = sign_approval(holder, unsigned(first), SEED)
    moved = console.post("/api/approve", json=approval_body("q:000002", for_first))
    assert moved.json() == _denied("consent: bad signature", "q:000002")


def test_a_one_time_key_signs_one_payment(console):
    holder = console.pair()
    assert console.pay(holder, SEED)["payment_id"] == "pay:000001"
    second = console.tool("quote_payment", QUOTE)
    reused = [
        console.approve(second, holder, SEED),
        console.approve(second, holder, holder),
    ]
    assert reused == [_denied("consent: key reused", "q:000002")] * 2
    assert _moved(console) == (1, 1)


def test_a_confirm_sent_twice_pays_once(console):
    holder = console.pair()
    first = console.pay(holder)
    again = console.tool("confirm_payment", {"quote_id": "q:000001"})
    assert again == first == PAID
    assert console.get("/api/receipt/pay:000002").status_code == 404
    assert _moved(console) == (1, 1)


def test_a_pairing_token_pairs_one_device(console):
    console.pair()
    _, intruder = generate_keypair()
    second = console.post(
        "/api/holder", json={"public_key": b64(intruder), "pairing": console.token}
    )
    assert (second.status_code, second.json()) == BAD
    assert console.get("/api/device").json() == {"holders": 1, "voice": False}


@pytest.mark.parametrize("key", SMALL_ORDER, ids=["identity", "order 8"])
def test_a_small_order_key_never_pairs(console, key):
    refused = console.post(
        "/api/holder", json={"public_key": b64(key), "pairing": console.token}
    )
    assert (refused.status_code, refused.json()) == BAD
    assert console.get("/api/device").json()["holders"] == 0
    # The refused key did not burn the token: the real device still pairs.
    console.pair()
    assert console.get("/api/device").json()["holders"] == 1


def test_a_pairing_token_lapses_after_ten_minutes(make_desk, serve):
    now = [1_000_000.0]
    desk, _ = make_desk(register=False)
    app = build_server(desk, ("pair-a", "pair-b"), clock=lambda: now[0])
    url = serve(app.streamable_http_app())

    def pair(token: str) -> httpx2.Response:
        _, key = generate_keypair()
        return httpx2.post(
            f"{url}/api/holder", json={"public_key": b64(key), "pairing": token}
        )

    now[0] += PAIRING_TTL_S
    assert pair("pair-a").json() == {"registered": True}
    now[0] += 1
    late = pair("pair-b")
    assert (late.status_code, late.json()) == BAD
    assert httpx2.get(f"{url}/api/device").json()["holders"] == 1


@pytest.mark.parametrize(
    "headers",
    [
        {**JSON, **FOREIGN},
        {"content-type": "text/plain"},
        {**JSON, "origin": "http://evil.example"},
    ],
)
def test_a_page_that_is_not_the_desk_cannot_approve(console, headers):
    holder = console.pair()
    quote = console.tool("quote_payment", QUOTE)
    approval = sign_approval(holder, unsigned(quote))
    body = approval_body(quote["quote_id"], approval)
    answer = console.post("/api/approve", content=json.dumps(body), headers=headers)
    assert (answer.status_code, answer.json()) == BAD
    status = console.tool("get_payment_status", {"quote_id": "q:000001"})
    assert status["status"] == "quoted"


@pytest.mark.parametrize(
    ("headers", "status", "body"),
    [
        ({"x-forwarded-for": "203.0.113.7"}, *LOCAL_ONLY),
        ({"forwarded": "for=203.0.113.7"}, *LOCAL_ONLY),
        (FOREIGN, *BAD),
    ],
)
def test_the_holder_copy_never_leaves_the_desks_machine(console, headers, status, body):
    console.pay(console.pair())
    answer = console.get("/api/receipt/pay:000001?disclose=all", headers=headers)
    assert (answer.status_code, answer.json()) == (status, body)


def test_the_holder_copy_stays_on_the_local_listener(tmp_path):
    split = Console(tmp_path, local_port=True).start()
    try:
        split.pay(split.pair())
        path = "/api/receipt/pay:000001"
        public = split.get(f"{path}?disclose=all")
        assert (public.status_code, public.json()) == LOCAL_ONLY
        assert split.get(path).status_code == 200
        local = httpx2.get(f"{split.local_url}{path}?disclose=all")
        assert (local.status_code, local.json()["payment_id"]) == (200, "pay:000001")
    finally:
        split.stop()


def test_nobody_but_the_device_can_unpair_it(console):
    console.pair()
    published = console.get("/api/keys").json()["holder_keys"][0]
    other = Ed25519PrivateKey.generate().sign(unpair_bytes(base64.b64decode(published)))
    for signature in (b"\x01" * 64, other):
        answer = console.post(
            "/api/holder/unpair",
            json={"public_key": published, "signature": b64(signature)},
        )
        assert answer.json() == {"unpaired": False}
    assert console.get("/api/device").json()["holders"] == 1


@pytest.mark.parametrize(
    "change",
    [{"amount_cents": -5}, {"amount_cents": 0}, {"reference": "A 991"}],
)
def test_a_malformed_quote_opens_nothing(console, change):
    assert console.tool("quote_payment", {**QUOTE, **change}) == {
        "status": "denied",
        "reason": "consent: malformed",
    }
    assert console.get("/api/pending").json() == {"pending": []}
