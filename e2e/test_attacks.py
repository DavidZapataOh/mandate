from collections.abc import Iterator
from pathlib import Path

import pytest

from e2e.attack_world import Console

JSON = {"content-type": "application/json"}

# (kind, layer, reason) for each pinned template: the layer that refuses it
# and its own refusal, as the console's attack panel names them.
TEMPLATES = [
    ("payee_swap", "model->gate", "recipient differs from intent"),
    ("amount_inflate", "model->gate", "amount differs from intent"),
    ("replay", "bank", "replay: jti consumed"),
    ("post_cert_mutation", "gate->bank", "mismatch: action hash differs"),
    ("scope_escalation", "delegation", "scope: target outside delegation"),
    ("mcp_exfil", "mcp", "denied: server undeclared"),
    ("forged_approval", "holder->gate", "consent: bad signature"),
]


@pytest.fixture(scope="module")
def pressed(tmp_path_factory) -> Iterator[tuple[Console, dict[str, dict]]]:
    console = Console(tmp_path_factory.mktemp("attacks")).start()
    try:
        lines = {}
        for kind, _, _ in TEMPLATES:
            answer = console.post("/api/attack", json={"kind": kind})
            assert answer.status_code == 200
            lines[kind] = answer.json()
        yield console, lines
    finally:
        console.stop()


@pytest.mark.parametrize(("kind", "layer", "reason"), TEMPLATES)
def test_each_template_dies_at_its_layer_and_moves_nothing(
    pressed, kind, layer, reason
):
    console, lines = pressed
    line = lines[kind]
    assert (line["source"], line["subject"]["origin"]) == ("attack", "template")
    subject = line["subject"]
    assert (subject["attack"], subject["layer"], subject["reason"]) == (
        kind,
        layer,
        reason,
    )
    assert (subject["blocked"], subject["moved_cents"]) == (True, 0)
    # The kill-cam replays exactly the line the press returned.
    served = console.get(f"/api/forensic/{line['seq']}")
    assert served.json() == line


def test_attacks_leave_the_desk_untouched(pressed):
    console, _ = pressed
    assert console.get("/api/registry").json() == {"seal": None}
    assert console.get("/api/receipt/pay:000001").status_code == 404
    report = console.post("/api/reconcile", json={}).json()
    assert (report["transfers"], report["certified"], report["unbacked"]) == (
        0,
        0,
        [],
    )


@pytest.mark.parametrize(
    ("body", "headers"),
    [
        (b'{"kind": "drain_the_account"}', JSON),
        (b'{"kind": 3}', JSON),
        (b'{"kind": "replay"}', {**JSON, "host": "evil.example:8765"}),
        (b'{"kind": "replay"}', {"content-type": "text/plain"}),
        (b'{"kind": "replay"}', {**JSON, "origin": "http://evil.example"}),
    ],
)
def test_a_press_that_is_unknown_or_not_this_sites_is_refused(pressed, body, headers):
    console, lines = pressed
    answer = console.post("/api/attack", content=body, headers=headers)
    assert (answer.status_code, answer.json()) == (400, {"error": "bad request"})
    last = max(line["seq"] for line in lines.values())
    assert console.get(f"/api/forensic/{last + 1}").status_code == 404


def test_attacks_never_write_the_durable_fences(tmp_path: Path):
    console = Console(tmp_path).start()
    try:
        for kind, _, _ in TEMPLATES:
            console.post("/api/attack", json={"kind": kind})
    finally:
        console.stop()
    console.start()
    try:
        holder = console.pair()
        paid = console.pay(holder)
        assert (paid["payment_id"], paid["quote_id"], paid["reason"]) == (
            "pay:000001",
            "q:000001",
            "ok: executed",
        )
        assert console.get("/api/provenance").json()["registry"]["leaves"] == 1
    finally:
        console.stop()
