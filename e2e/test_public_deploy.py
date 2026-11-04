import base64
import os
import re
import subprocess
import time
from collections.abc import Iterator

import anyio
import httpx2
import pytest
from mcp import Client

from e2e.test_explorer_walkthrough import CLI, CONSOLE, _free_port, _missing, _tool
from gate.certs import generate_keypair

CSP = (
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)
PUBLIC = "desk.example.com"
PAIR = re.compile(r"Pair the holder device: https://desk\.example\.com/app/#pair=(\S+)")
PAGES = (
    "/console/",
    "/console/explorer.html",
    "/console/command.html",
    "/console/holder.html",
    "/app/",
)
HOLDER_COPY = "/api/receipt/pay:000001?disclose=all"
# The operator rounds page the bank or public calendars: local listener only.
ROUNDS = ("/api/reconcile", "/api/anchor")
# What an HTTPS proxy on this machine adds to each request it relays.
PROXIED = {
    "host": PUBLIC,
    "x-forwarded-proto": "https",
    "x-forwarded-for": "203.0.113.9",
}
# A websocket upgrade relayed to /mcp, as a proxy passing upgrades would send it.
UPGRADE = {
    "connection": "upgrade",
    "upgrade": "websocket",
    "sec-websocket-version": "13",
    "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
}


@pytest.fixture
def deployed() -> Iterator[tuple[str, str, str]]:
    missing = _missing()
    if missing is not None:
        if os.environ.get("MANDATE_WALKTHROUGH") == "1":
            pytest.fail(f"walkthrough: {missing}")
        pytest.skip(f"walkthrough: {missing}")
    port, local = _free_port(), _free_port()
    proc = subprocess.Popen(  # noqa: S603
        [
            str(CLI), "--port", str(port), "--local-port", str(local),
            "--public-host", PUBLIC, "--trusted-proxy", "127.0.0.1",
            "--console-dir", str(CONSOLE / "dist"),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )  # fmt: skip
    try:
        assert proc.stdout is not None
        found = PAIR.fullmatch(proc.stdout.readline().strip())
        assert found is not None
        public = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 15
        while True:
            try:
                httpx2.get(f"{public}/api/health", headers=PROXIED)
                break
            except httpx2.TransportError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        yield public, f"http://127.0.0.1:{local}", found.group(1)
    finally:
        proc.terminate()
        proc.wait(10)


def test_a_proxied_console_keeps_mcp_and_holder_copies_local(
    deployed: tuple[str, str, str],
) -> None:
    public, local, token = deployed
    # A proxy that rewrites Host to its upstream and adds nothing (nginx's default).
    bare = {"host": public.removeprefix("http://")}
    _, holder_pub = generate_keypair()
    pairing = {"public_key": base64.b64encode(holder_pub).decode(), "pairing": token}
    with httpx2.Client(base_url=public) as http:
        policies = [http.get(p, headers=PROXIED) for p in PAGES]
        mcp = [http.post("/mcp", json={}, headers=h) for h in (PROXIED, bare)]
        socket_mcp = [
            http.get("/mcp", headers={**h, **UPGRADE}) for h in (PROXIED, bare)
        ]
        copies = [http.get(HOLDER_COPY, headers=h) for h in (PROXIED, bare)]
        rounds = [
            http.post(path, json={}, headers=h)
            for path in ROUNDS
            for h in (PROXIED, bare)
        ]
        foreign = http.get("/api/pending", headers={"host": "evil.example"})
        paired = http.post(
            "/api/holder",
            json=pairing,
            headers={**PROXIED, "origin": f"https://{PUBLIC}"},
        )
        health = http.get("/api/health", headers=PROXIED)
    with httpx2.Client(base_url=local) as http:
        local_copy = http.get(HOLDER_COPY)
        local_anchor = http.post("/api/anchor", json={})
        local_reconcile = http.post("/api/reconcile", json={})
        # The SDK's own Host check is the second fence on the local socket.
        local_foreign_mcp = http.post("/mcp", json={}, headers={"host": "evil.example"})
    assert [
        (r.status_code, r.headers["content-security-policy"]) for r in policies
    ] == [(200, CSP)] * len(PAGES)
    assert [(r.status_code, r.json()) for r in mcp + socket_mcp + rounds] == [
        (404, {"error": "not found"})
    ] * 8
    assert [(r.status_code, r.json()) for r in copies] == [
        (403, {"error": "holder copy is local only"})
    ] * 2
    assert (foreign.status_code, foreign.json()) == (400, {"error": "bad request"})
    assert paired.json() == {"registered": True}
    assert (health.json()["rail"], health.json()["bank"]) == ("simulated", None)
    # The local listener answers them: no receipt yet, no public anchor started.
    assert local_copy.status_code == 404
    assert local_copy.json() != {"error": "holder copy is local only"}
    assert (local_anchor.status_code, local_anchor.json()) == (
        409,
        {"error": "public anchor off"},
    )
    assert local_reconcile.status_code == 200
    assert local_foreign_mcp.status_code == 421

    async def status() -> dict[str, object]:
        async with Client(f"{local}/mcp") as client:
            return await _tool(client, "get_payment_status", {"quote_id": "q:000009"})

    assert anyio.run(status) == {"status": "unknown", "quote_id": "q:000009"}


@pytest.mark.live
def test_the_public_host_passes_the_deploy_checks() -> None:
    url = os.environ.get("MANDATE_PUBLIC_URL")
    if not url or not url.startswith("https://"):
        pytest.skip("set MANDATE_PUBLIC_URL to the deployed https:// origin")
    spoofed = {"x-forwarded-for": "127.0.0.1", "x-real-ip": "127.0.0.1"}
    with httpx2.Client(base_url=url, timeout=20) as http:
        policies = [http.get(p) for p in PAGES]
        mcp = http.post("/mcp", json={})
        rounds = [http.post(path, json={}, headers=spoofed) for path in ROUNDS]
        copy = http.get(HOLDER_COPY, headers=spoofed)
        foreign = http.get("/api/pending", headers={"host": "evil.example"})
        health = http.get("/api/health")
    assert [
        (r.status_code, r.headers["content-security-policy"]) for r in policies
    ] == [(200, CSP)] * len(PAGES)
    assert [r.status_code for r in (mcp, *rounds)] == [404] * 3
    assert (copy.status_code, copy.json()) == (
        403,
        {"error": "holder copy is local only"},
    )
    assert foreign.status_code >= 400
    assert set(health.json()) == {"rail", "reconciled_at", "bank"}
