import base64
import json

import httpx2
import pytest

from gate.certs import public_key_of
from swarm.server import build_server
from swarm.test_receipt import AUDITOR, GATE, GOLDEN, HOLDER
from swarm.test_server import FOREIGN, PAIR, _http

PUBLIC = "mandate.example"
CONSENT_SIGNATURE = (
    "OORzeXDe6eaiUsW4PdqrQGhplcplmWCgI+yt3WYVkQR34lDISLG3GHAMrfd0amy"
    "/IncXYk95hGubzPgB5jg+AQ=="
)
HOLDER_KEY = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q="


def _paid(make_desk, sign_quote):
    desk, holder = make_desk(gate_key=GATE, holder_key=HOLDER)
    q = desk.quote("acme-991", 20000, "USD", "A-991")
    desk.approve(q["quote_id"], sign_quote(holder, q))
    desk.confirm(q["quote_id"])
    return desk


def _public(desk):
    app = build_server(desk, PAIR, ("127.0.0.1", "localhost", PUBLIC))
    transport = httpx2.ASGITransport(app=app.streamable_http_app())
    return httpx2.AsyncClient(transport=transport, base_url=f"http://{PUBLIC}")


def _disclosed(receipt):
    _, *texts, _ = receipt["sd"].split("~")
    return [json.loads(base64.urlsafe_b64decode(t + "==")) for t in texts]


@pytest.mark.anyio
async def test_keys_route_publishes_gate_and_holder_keys(make_desk, sign_quote):
    desk = _paid(make_desk, sign_quote)
    async with _http(desk) as http:
        resp = await http.get("/api/keys")
    assert resp.status_code == 200
    assert resp.json() == {
        "gate_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
        "holder_keys": [HOLDER_KEY],
    }


@pytest.mark.anyio
async def test_receipt_route_serves_the_auditor_copy(make_desk, sign_quote):
    desk = _paid(make_desk, sign_quote)
    async with _http(desk) as http:
        found = await http.get("/api/receipt/pay%3A000001")
        plain = await http.get("/api/receipt/pay:000001")
        full = await http.get("/api/receipt/pay:000001?disclose=all")
        missing = await http.get("/api/receipt/pay:000002")
    assert found.json() == json.loads(AUDITOR.read_text())
    assert plain.json() == found.json()
    assert full.json() == json.loads(GOLDEN.read_text())
    assert (missing.status_code, missing.json()) == (404, {"error": "not found"})


@pytest.mark.anyio
async def test_holder_copy_is_local_only(make_desk, sign_quote):
    desk = _paid(make_desk, sign_quote)
    async with _http(desk) as local:
        loopback = await local.get(
            "/api/receipt/pay:000001?disclose=all", headers={"host": "127.0.0.1:8765"}
        )
    async with _public(desk) as public:
        shared = await public.get("/api/receipt/pay:000001")
        refused = await public.get("/api/receipt/pay:000001?disclose=all")
    assert loopback.json() == json.loads(GOLDEN.read_text())
    assert shared.json() == json.loads(AUDITOR.read_text())
    assert (refused.status_code, refused.json()) == (
        403,
        {"error": "holder copy is local only"},
    )


def _from(desk, client, host="127.0.0.1"):
    app = build_server(desk, PAIR, ("127.0.0.1", "localhost", "::1", PUBLIC))
    transport = httpx2.ASGITransport(app=app.streamable_http_app(), client=client)
    return httpx2.AsyncClient(transport=transport, base_url=f"http://{host}")


HOLDER_COPY = "/api/receipt/pay:000001?disclose=all"
LOCAL_ONLY = (403, {"error": "holder copy is local only"})


@pytest.mark.anyio
async def test_holder_copy_refuses_a_spoofed_host_from_a_remote_client(
    make_desk, sign_quote
):
    desk = _paid(make_desk, sign_quote)
    async with _from(desk, ("192.0.2.7", 5000)) as remote:
        spoofed = await remote.get(HOLDER_COPY, headers={"host": "localhost"})
        upper = await remote.get(HOLDER_COPY, headers={"host": "LOCALHOST:9"})
    assert (spoofed.status_code, spoofed.json()) == LOCAL_ONLY
    assert (upper.status_code, upper.json()) == LOCAL_ONLY


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("client", "host"),
    [
        (("127.0.0.1", 5000), "127.0.0.1:8765"),
        (("127.0.0.1", 5000), "LocalHost"),
        (("::1", 5000), "[::1]:8765"),
        (("::ffff:127.0.0.1", 5000), "localhost:8765"),
    ],
)
async def test_holder_copy_serves_a_loopback_client_on_a_loopback_host(
    make_desk, sign_quote, client, host
):
    desk = _paid(make_desk, sign_quote)
    async with _from(desk, client) as local:
        resp = await local.get(HOLDER_COPY, headers={"host": host})
    assert resp.status_code == 200
    assert resp.json() == json.loads(GOLDEN.read_text())


@pytest.mark.anyio
async def test_holder_copy_refuses_a_loopback_client_on_a_public_host(
    make_desk, sign_quote
):
    desk = _paid(make_desk, sign_quote)
    async with _from(desk, ("127.0.0.1", 5000)) as local:
        resp = await local.get(HOLDER_COPY, headers={"host": PUBLIC})
    assert (resp.status_code, resp.json()) == LOCAL_ONLY


@pytest.mark.anyio
@pytest.mark.parametrize(
    "header",
    [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "cf-connecting-ip",
    ],
)
async def test_holder_copy_refuses_a_proxied_loopback_request(
    make_desk, sign_quote, header
):
    desk = _paid(make_desk, sign_quote)
    async with _from(desk, ("127.0.0.1", 5000)) as local:
        resp = await local.get(
            HOLDER_COPY, headers={"host": "127.0.0.1:8765", header: "198.51.100.4"}
        )
        shared = await local.get(
            "/api/receipt/pay:000001",
            headers={"host": "127.0.0.1:8765", header: "198.51.100.4"},
        )
    assert (resp.status_code, resp.json()) == LOCAL_ONLY
    assert shared.json() == json.loads(AUDITOR.read_text())


@pytest.mark.anyio
async def test_auditor_copy_withholds_personal_fields(make_desk, sign_quote):
    desk = _paid(make_desk, sign_quote)
    async with _public(desk) as public:
        shared = (await public.get("/api/receipt/pay:000001")).json()
    text = json.dumps(shared)
    names = {item[1] for item in _disclosed(shared)}
    assert not names & {"action_salt", "signature", "holder_key", "targets"}
    assert "01" * 32 not in text
    assert CONSENT_SIGNATURE not in text
    assert HOLDER_KEY not in text
    assert "holder_key" not in text


@pytest.mark.anyio
@pytest.mark.parametrize("query", ["?disclose=amount", "?disclose=all&x=1", "?full=1"])
async def test_receipt_route_refuses_other_disclosures(make_desk, sign_quote, query):
    desk = _paid(make_desk, sign_quote)
    async with _http(desk) as http:
        resp = await http.get(f"/api/receipt/pay:000001{query}")
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})


@pytest.mark.anyio
async def test_registry_route_publishes_the_latest_seal(make_desk, sign_quote):
    fresh, _ = make_desk()
    desk = _paid(make_desk, sign_quote)
    async with _http(fresh) as http:
        empty = await http.get("/api/registry")
    async with _http(desk) as http:
        sealed = await http.get("/api/registry")
    assert empty.json() == {"seal": None}
    assert sealed.json() == {"seal": json.loads(GOLDEN.read_text())["registry"]["seal"]}


@pytest.mark.anyio
@pytest.mark.parametrize("path", ["/api/keys", "/api/registry", "/api/receipt/pay:1"])
async def test_proof_routes_refuse_foreign_hosts(make_desk, path):
    desk, _ = make_desk()
    async with _http(desk) as http:
        resp = await http.get(path, headers=FOREIGN)
    assert (resp.status_code, resp.json()) == (400, {"error": "bad request"})


@pytest.mark.anyio
async def test_receipt_route_answers_not_found_when_the_receipt_failed(
    make_desk, sign_quote, monkeypatch
):
    def broken(*args, **kwargs):
        raise ValueError("receipt: action salt must be 32 bytes")

    monkeypatch.setattr("swarm.desk.proof_receipt", broken)
    desk = _paid(make_desk, sign_quote)
    async with _http(desk) as http:
        resp = await http.get("/api/receipt/pay:000001")
    assert (resp.status_code, resp.json()) == (404, {"error": "not found"})


@pytest.mark.anyio
async def test_keys_route_publishes_every_key_that_ever_paired(make_desk, sign_quote):
    desk = _paid(make_desk, sign_quote)
    holder_id = desk.register_holder(public_key_of(b"\x03" * 32))
    desk.unpair_holder(holder_id)
    async with _http(desk) as http:
        keys = (await http.get("/api/keys")).json()
    assert keys["holder_keys"] == [
        "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=",
        "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=",
    ]
    assert desk.holder_keys == (public_key_of(HOLDER),)
