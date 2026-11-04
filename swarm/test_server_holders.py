import hmac

import pytest

from gate.certs import public_key_of
from swarm import server
from swarm.hub import EventHub
from swarm.server import build_server
from swarm.test_holders import UNPAIR_SIGNATURE
from swarm.test_server import _asgi, _b64

TOKENS = ("tok-a-0123456789", "tok-b-0123456789", "tok-c-0123456789")
HOLDER = public_key_of(b"\x02" * 32)


def _key(n):
    return public_key_of(bytes([n]) * 32)


def _app(desk, tokens=TOKENS, hub=None):
    return _asgi(build_server(desk, tokens, hub=hub).streamable_http_app())


async def _pair(http, key, token):
    body = {"public_key": _b64(key), "pairing": token}
    return await http.post("/api/holder", json=body)


@pytest.mark.anyio
async def test_each_pairing_token_pairs_one_device(make_desk):
    desk, _ = make_desk(register=False)
    async with _app(desk) as http:
        first = await _pair(http, _key(3), TOKENS[0])
        spent = await _pair(http, _key(4), TOKENS[0])
        second = await _pair(http, _key(4), TOKENS[2])
    assert first.json() == second.json() == {"registered": True}
    assert (spent.status_code, spent.json()) == (400, {"error": "bad request"})
    assert desk.holder_keys == (_key(3), _key(4))


@pytest.mark.anyio
async def test_a_wrong_token_spends_none(make_desk):
    desk, _ = make_desk(register=False)
    async with _app(desk) as http:
        wrong = await _pair(http, _key(3), TOKENS[0] + "x")
        paired = [
            (await _pair(http, _key(n), t)).json()
            for n, t in zip((3, 4, 5), TOKENS, strict=True)
        ]
    assert wrong.status_code == 400
    assert paired == [{"registered": True}] * 3


@pytest.mark.anyio
async def test_every_outstanding_token_is_compared(make_desk, monkeypatch):
    calls = []
    real = hmac.compare_digest

    def counted(a, b):
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(server.hmac, "compare_digest", counted)
    desk, _ = make_desk(register=False)
    async with _app(desk) as http:
        await _pair(http, _key(3), TOKENS[0])
        first = len(calls)
        await _pair(http, _key(4), "no-such-token-000")
        second = len(calls) - first
    assert (first, second) == (3, 2)


@pytest.mark.anyio
async def test_a_device_unpairs_itself_and_cannot_pair_again(make_desk):
    desk, _ = make_desk(register=False)
    body = {"public_key": _b64(HOLDER), "signature": UNPAIR_SIGNATURE}
    async with _app(desk) as http:
        await _pair(http, HOLDER, TOKENS[0])
        once = await http.post("/api/holder/unpair", json=body)
        twice = await http.post("/api/holder/unpair", json=body)
        again = await _pair(http, HOLDER, TOKENS[1])
    assert (once.json(), twice.json()) == ({"unpaired": True}, {"unpaired": False})
    assert again.json() == {"registered": False}
    assert desk.holder_keys == ()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "body",
    [
        {"public_key": _b64(HOLDER)},
        {"public_key": _b64(HOLDER), "signature": "%%%"},
        {"public_key": _b64(HOLDER[:31]), "signature": UNPAIR_SIGNATURE},
        {"public_key": 7, "signature": UNPAIR_SIGNATURE},
    ],
)
async def test_unpair_route_rejects_bad_requests(make_desk, body):
    desk, _ = make_desk(register=False)
    desk.register_holder(HOLDER)
    async with _app(desk) as http:
        resp = await http.post("/api/holder/unpair", json=body)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})
    assert desk.holder_keys == (HOLDER,)


@pytest.mark.anyio
async def test_device_route_counts_paired_holders(make_desk):
    desk, _ = make_desk(register=False)
    body = {"public_key": _b64(HOLDER), "signature": UNPAIR_SIGNATURE}
    async with _app(desk) as http:
        none = (await http.get("/api/device")).json()
        await _pair(http, HOLDER, TOKENS[0])
        await _pair(http, _key(3), TOKENS[1])
        two = (await http.get("/api/device")).json()
        await http.post("/api/holder/unpair", json=body)
        one = (await http.get("/api/device")).json()
    # `voice` is the holder page's microphone flag; it names no device.
    assert [none, two, one] == [
        {"holders": 0, "voice": False},
        {"holders": 2, "voice": False},
        {"holders": 1, "voice": False},
    ]


@pytest.mark.anyio
async def test_pairing_and_unpairing_publish_no_line(make_desk):
    desk, _ = make_desk(register=False)
    hub = EventHub()
    body = {"public_key": _b64(HOLDER), "signature": UNPAIR_SIGNATURE}
    async with _app(desk, hub=hub) as http:
        await _pair(http, HOLDER, TOKENS[0])
        await http.post("/api/holder/unpair", json=body)
        lines = (await http.get("/api/lines")).json()
    assert lines == []


@pytest.mark.anyio
async def test_a_small_order_key_is_refused_before_the_token_is_spent(make_desk):
    desk, _ = make_desk(register=False)
    async with _app(desk) as http:
        weak = await _pair(http, bytes.fromhex("01" + "00" * 31), TOKENS[0])
        real = await _pair(http, _key(3), TOKENS[0])
    assert (weak.status_code, weak.json()) == (400, {"error": "bad request"})
    assert real.json() == {"registered": True}
    assert desk.holder_keys == (_key(3),)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("elapsed", "want"),
    [(600, (200, {"registered": True})), (601, (400, {"error": "bad request"}))],
    ids=["at ten minutes", "past ten minutes"],
)
async def test_a_pairing_token_lapses_after_ten_minutes(make_desk, elapsed, want):
    desk, _ = make_desk(register=False)
    now = [1800001000.0]
    app = build_server(desk, TOKENS, clock=lambda: now[0]).streamable_http_app()
    now[0] += elapsed
    async with _asgi(app) as http:
        resp = await _pair(http, _key(3), TOKENS[0])
    assert (resp.status_code, resp.json()) == want
