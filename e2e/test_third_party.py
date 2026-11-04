import base64
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx2
import pytest

from bank.conftest import Cassette
from bank.increase import IncreaseRail
from e2e.attack_world import ROOT, Console
from e2e.test_bank_attacks import ACCOUNTS, HELD, _pay, _sandbox
from gate.anchor_public import anchor_digest_of

CONSOLE = ROOT / "console"
VITEST = ("npx", "vitest", "run", "src/explorer/third-party.test.ts")


def _missing() -> str | None:
    if shutil.which("npx") is None:
        return "npx is not on PATH"
    if not (CONSOLE / "node_modules" / ".bin" / "vitest").exists():
        return "console dependencies missing: run npm ci in console/"
    return None


def _first_payment(tmp: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    console = Console(tmp, durable=False).start()
    try:
        paid = console.pay(console.pair())
        pid = paid["payment_id"]
        return (
            console.get("/api/keys").json(),
            console.get(f"/api/receipt/{pid}?disclose=all").json(),
            console.get(f"/api/receipt/{pid}").json(),
        )
    finally:
        console.stop()


def test_a_third_party_verifies_live_receipts_and_refuses_forgeries(
    make_desk, serve, tmp_path
):
    missing = _missing()
    if missing is not None:
        if os.environ.get("MANDATE_THIRD_PARTY") == "1":
            pytest.fail(f"third party: {missing}")
        pytest.skip(f"third party: {missing}")
    keys, holder, auditor = _first_payment(tmp_path / "desk")
    _, other, _ = _first_payment(tmp_path / "other")
    cassette = Cassette("balance_lookup", (200, HELD))
    rail = IncreaseRail(cassette.client(), ACCOUNTS)
    url, _, sandbox_holder = _sandbox(make_desk, serve, rail)
    paid = _pay(url, sandbox_holder)
    # The digest this desk would stamp, computed by the desk's own code, so the
    # explorer's recomputation is checked against a second implementation.
    gate_key = base64.b64decode(keys["gate_key"])
    case = {
        "keys": keys,
        "holder": holder,
        "auditor": auditor,
        "other_desk": other,
        "anchor_digest": anchor_digest_of(holder["registry"]["seal"], gate_key).hex(),
        "sandbox": httpx2.get(
            f"{url}/api/receipt/{paid['payment_id']}?disclose=all"
        ).json(),
        "sandbox_keys": httpx2.get(f"{url}/api/keys").json(),
    }
    path = tmp_path / "case.json"
    path.write_text(json.dumps(case))
    run = subprocess.run(  # noqa: S603
        VITEST,
        cwd=CONSOLE,
        env={**os.environ, "MANDATE_CASE": str(path)},
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert run.returncode == 0, run.stdout[-3000:] + run.stderr[-2000:]
    assert "Tests  13 passed (13)" in run.stdout
