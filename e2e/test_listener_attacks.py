"""A published console's listeners, forwarded headers and doctor under attack."""

import hashlib
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import anyio
import httpx2
import pytest
from mcp import Client

from e2e.attack_world import CONSOLE_CMD, ROOT, Console, b64, free_port
from gate.certs import generate_keypair

NOT_FOUND = (404, {"error": "not found"})
LOCAL_ONLY = (403, {"error": "holder copy is local only"})
HOLDER_COPY = "/api/receipt/pay:000001?disclose=all"
# What a neighbour adds to look like the proxy, or like this machine.
SPOOFED = {
    "x-forwarded-for": "127.0.0.1",
    "x-forwarded-proto": "https",
    "x-real-ip": "127.0.0.1",
    "forwarded": "for=127.0.0.1;proto=https",
}
UPGRADE = {
    "connection": "upgrade",
    "upgrade": "websocket",
    "sec-websocket-version": "13",
    "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
}
PUBLIC = "desk.example.com"
SENTINELS = {
    "INCREASE_SANDBOX_API_KEY": "sandbox_key_SENTINEL_doctor_1",
    "INCREASE_HOLDER_API_KEY": "holder_key_SENTINEL_doctor_2",
    "INCREASE_SANDBOX_WEBHOOK_SECRET": "webhook_SENTINEL_doctor_3",
}


@pytest.fixture(scope="module")
def split(tmp_path_factory) -> Iterator[Console]:
    served = Console(tmp_path_factory.mktemp("split"), local_port=True).start()
    try:
        holder = served.pair()
        assert served.pay(holder)["payment_id"] == "pay:000001"
        yield served
    finally:
        served.stop()


@pytest.mark.parametrize(
    ("method", "path", "headers"),
    [
        ("POST", "/mcp", {}),
        ("POST", "/mcp", SPOOFED),
        ("POST", "/mcp/", {}),
        ("POST", "/mcp/messages", {}),
        ("GET", "/mcp", UPGRADE),
        ("GET", "/mcp", {**UPGRADE, **SPOOFED}),
        ("POST", "/api/reconcile", {}),
        ("POST", "/api/reconcile", SPOOFED),
        ("POST", "/api/anchor", {}),
        ("POST", "/api/anchor", SPOOFED),
    ],
    ids=[
        "mcp", "mcp spoofed", "mcp slash", "mcp messages", "mcp websocket",
        "mcp websocket spoofed", "reconcile", "reconcile spoofed", "anchor",
        "anchor spoofed",
    ],
)  # fmt: skip
def test_the_public_listener_never_reaches_the_local_only_paths(
    split, method, path, headers
):
    answer = httpx2.request(method, f"{split.url}{path}", json={}, headers=headers)
    assert (answer.status_code, answer.json()) == NOT_FOUND


def test_the_agents_own_client_opens_no_session_on_the_public_listener(split):
    async def session() -> None:
        async with Client(f"{split.url}/mcp") as client:
            await client.call_tool("get_payment_status", {"quote_id": "q:000001"})

    with pytest.raises(Exception):  # noqa: B017, PT011
        anyio.run(session)
    # The same call on the local listener answers.
    found = split.tool("get_payment_status", {"quote_id": "q:000001"})
    assert found["status"] == "confirmed"


@pytest.mark.parametrize(
    "headers",
    [
        {"x-forwarded-for": "127.0.0.1"},
        {"x-real-ip": "127.0.0.1"},
        {"forwarded": "for=127.0.0.1"},
        {"host": "evil.example"},
    ],
    ids=["x-forwarded-for", "x-real-ip", "forwarded", "foreign host"],
)
def test_the_holder_copy_is_refused_even_on_the_local_listener_when_relayed(
    split, headers
):
    relayed = httpx2.get(f"{split.local_url}{HOLDER_COPY}", headers=headers)
    want = (400, {"error": "bad request"}) if "host" in headers else LOCAL_ONLY
    assert (relayed.status_code, relayed.json()) == want
    public = httpx2.get(f"{split.url}{HOLDER_COPY}")
    assert (public.status_code, public.json()) == LOCAL_ONLY
    direct = httpx2.get(f"{split.local_url}{HOLDER_COPY}")
    assert (direct.status_code, direct.json()["payment_id"]) == (200, "pay:000001")


def test_the_local_listener_still_answers_the_rounds(split):
    reconciled = httpx2.post(f"{split.local_url}/api/reconcile", json={})
    anchored = httpx2.post(f"{split.local_url}/api/anchor", json={})
    assert reconciled.status_code == 200
    assert (anchored.status_code, anchored.json()) == (
        409,
        {"error": "public anchor off"},
    )


@pytest.mark.parametrize(
    ("proxy", "want"),
    [
        ("192.0.2.1", {"error": "bad request"}),
        ("127.0.0.1", {"registered": True}),
    ],
    ids=["a neighbour that is not the proxy", "the named proxy"],
)
def test_only_the_named_proxy_is_believed_about_https(tmp_path, proxy, want):
    served = Console(
        tmp_path,
        local_port=True,
        extra=("--public-host", PUBLIC, "--trusted-proxy", proxy),
    ).start()
    try:
        _, holder_pub = generate_keypair()
        paired = served.post(
            "/api/holder",
            json={"public_key": b64(holder_pub), "pairing": served.token},
            headers={
                "host": PUBLIC,
                "x-forwarded-proto": "https",
                "x-forwarded-for": "203.0.113.9",
                "origin": f"https://{PUBLIC}",
            },
        )
        assert paired.json() == want
    finally:
        served.stop()


def _snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        if path.is_file()
        else "dir"
        for path in sorted(root.rglob("*"))
    }


def _doctor(*argv: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **SENTINELS}
    return subprocess.run(  # noqa: S603
        [*CONSOLE_CMD, "--doctor", *argv],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )


def test_the_doctor_creates_no_state(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>Mandate</title>")
    before = _snapshot(tmp_path)
    ran = _doctor(
        "--port", str(free_port()), "--console-dir", str(dist),
        "--state-dir", str(tmp_path / "state"), "--local-port", str(free_port()),
    )  # fmt: skip
    assert (ran.returncode, ran.stdout.splitlines()[-1]) == (0, "doctor: ready")
    assert _snapshot(tmp_path) == before
    assert not any(v in ran.stdout + ran.stderr for v in SENTINELS.values())


def test_the_doctor_leaves_a_desks_state_as_it_was(tmp_path):
    served = Console(tmp_path).start()
    try:
        assert served.pay(served.pair())["payment_id"] == "pay:000001"
    finally:
        served.stop()
    before = _snapshot(tmp_path)
    assert any(name.startswith("state/") for name in before)
    ran = _doctor(
        "--port", str(free_port()), "--console-dir", str(tmp_path / "dist"),
        "--state-dir", str(served.state_dir),
    )  # fmt: skip
    assert (ran.returncode, ran.stdout.splitlines()[-1]) == (0, "doctor: ready")
    assert _snapshot(tmp_path) == before
    assert not any(v in ran.stdout + ran.stderr for v in SENTINELS.values())
    again = Console(tmp_path).start()
    try:
        assert again.pay(again.pair())["payment_id"] == "pay:000002"
    finally:
        again.stop()
