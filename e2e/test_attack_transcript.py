import json
from pathlib import Path
from typing import Any

from e2e.attack_world import QUOTE, Console, approval_body
from e2e.test_attacks import TEMPLATES
from gate.certs import generate_keypair
from gate.consent import HolderApproval
from swarm.console_line import read_console_line
from swarm.test_console_attacks import _fingerprint

ZERO = HolderApproval(b"\x00" * 64, b"\x00" * 32, b"\x00" * 64)
SEED = b"\x81" * 32
# What each step of the script decides: status, reason, quote, payment.
DECISIONS = [
    ("quoted", None, "q:000001", None),
    ("denied", "consent: bad signature", "q:000001", None),
    ("denied", "consent: bad signature", "q:000001", None),
    ("approved", None, "q:000001", None),
    ("confirmed", "ok: executed", "q:000001", "pay:000001"),
    ("confirmed", "ok: executed", "q:000001", "pay:000001"),
    ("quoted", None, "q:000002", None),
    ("denied", "consent: key reused", "q:000002", None),
]


def _decided(answer: dict[str, Any]) -> tuple[Any, ...]:
    keys = ("status", "reason", "quote_id", "payment_id")
    return tuple(answer.get(k) for k in keys)


def _transcript(console: Console) -> tuple[list[Any], list[Any]]:
    lines = []
    for kind, _, _ in TEMPLATES:
        text = console.post("/api/attack", json={"kind": kind}).text
        lines.append(
            {"seq": json.loads(text)["seq"], **_fingerprint(read_console_line(text))}
        )
    first = console.tool("quote_payment", QUOTE)
    answers = [console.tool("confirm_payment", {"quote_id": "q:000001"})]
    answers.append(
        console.post("/api/approve", json=approval_body("q:000001", ZERO)).json()
    )
    holder = console.pair()
    answers.append(console.approve(first, generate_keypair()[0]))
    answers.append(console.approve(first, holder, SEED))
    answers.append(console.tool("confirm_payment", {"quote_id": "q:000001"}))
    answers.append(console.tool("confirm_payment", {"quote_id": "q:000001"}))
    second = console.tool("quote_payment", QUOTE)
    answers.append(second)
    answers.append(console.approve(second, holder, SEED))
    return lines, [_decided(a) for a in answers]


def _run(tmp: Path) -> tuple[list[Any], list[Any]]:
    console = Console(tmp).start()
    try:
        return _transcript(console)
    finally:
        console.stop()


def test_the_suite_decides_the_same_on_every_run(tmp_path):
    first = _run(tmp_path / "first")
    second = _run(tmp_path / "second")
    assert first == second
    lines, decisions = first
    assert [line["seq"] for line in lines] == [1, 2, 3, 4, 5, 6, 7]
    assert decisions == DECISIONS
