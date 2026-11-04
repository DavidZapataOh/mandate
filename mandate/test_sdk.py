import json
import subprocess
import sys
from pathlib import Path

import pytest

from bank.api import Bank
from bank.verifier import Verifier
from gate.cava import Freshness, action_commitment
from gate.policy import Intent, Policy, Rule, Verdict
from gate.shim import Mode, RawCall
from mandate.cli import main
from mandate.client import (
    RunRequest,
    build_bank,
    load_policy,
    run_governed,
    to_proposed,
)

TS = 1800000000
NOW = 1800000100
NONCE = "dd11ee22ff3300445566778899001122"
SDK_COMMITMENT = "c9dc2e19064a73f725472251e018253ba08ca25852782f15fe50ef272d920070"


def _call() -> RawCall:
    return RawCall(
        runtime="cli",
        executable="bank.pay",
        operation="transfer",
        args=(
            ("amount", "20000"),
            ("currency", "USD"),
            ("from", "checking-881"),
            ("to", "acme-991"),
            ("ref", "A-991"),
        ),
        category="payments",
        evidence_refs=(),
        reversible=False,
    )


def _policy() -> Policy:
    return Policy(
        policy_id="payments",
        version=1,
        rules=(
            Rule(
                rule_id="pay-exact",
                actor="cli:bank.pay",
                operation="transfer",
                target="to:acme-991",
                amount_exact=True,
                amount_lte_cents=None,
                approval_required=False,
            ),
        ),
    )


def _intent() -> Intent:
    return Intent(
        amount_cents=20000,
        currency="USD",
        recipient="acme-991",
        reference="A-991",
    )


def _request(
    private_key: bytes, mode: Mode = Mode.ENFORCE, salt: bytes | None = None
) -> RunRequest:
    return RunRequest(
        call=_call(),
        policy=_policy(),
        intent=_intent(),
        private_key=private_key,
        mode=mode,
        now=NOW,
        nonce=NONCE,
        timestamp=TS,
        scope="mandate-cli",
        reasoning_commitment="00" * 32,
        revocation_index=0,
        salt=salt,
    )


def test_run_governed(keypair):
    priv, pub = keypair
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = run_governed(_request(priv), bank, Verifier(pub))
    assert result.verdict is Verdict.MET
    assert result.reason == "ok: executed"
    assert result.certificate is not None
    assert result.event.event_id == f"evt:{NONCE}"
    assert result.payment is not None
    assert result.payment.payment_id == "pay:000001"
    assert bank.get_balance("checking-881") == 30000


def test_shadow_never_executes(keypair):
    priv, pub = keypair
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = run_governed(_request(priv, Mode.SHADOW), bank, Verifier(pub))
    assert result.verdict is Verdict.MET
    assert (result.certificate, result.payment) == (None, None)
    assert bank.get_balance("checking-881") == 50000


def test_to_proposed_roundtrip():
    from gate.shim import canonize

    action = canonize(_call(), NONCE, TS)
    proposed = to_proposed(action)
    assert (proposed.executable, proposed.operation, proposed.targets) == (
        action.executable,
        action.operation,
        action.targets,
    )
    assert (proposed.freshness.nonce, proposed.freshness.timestamp) == (
        NONCE,
        TS,
    )


def test_load_policy(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        '{"policy_id": "payments", "version": 1, "rules": ['
        '{"rule_id": "pay-exact", "actor": "cli:bank.pay", '
        '"operation": "transfer", "target": "to:acme-991", '
        '"amount_exact": true, "amount_lte_cents": null, '
        '"approval_required": false}]}'
    )
    assert load_policy(path) == _policy()
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError, match="invalid policy file"):
        load_policy(bad)
    missing = tmp_path / "missing.json"
    with pytest.raises(FileNotFoundError):
        load_policy(missing)


def test_build_bank_same_account():
    bank = build_bank("checking-881", "checking-881", 100)
    assert bank.get_balance("checking-881") == 100
    assert build_bank("a", "b", 50).get_balance("b") == 0


POLICY = {
    "policy_id": "payments",
    "version": 1,
    "rules": [
        {
            "rule_id": "pay-exact",
            "actor": "cli:bank.pay",
            "operation": "transfer",
            "target": "to:acme-991",
            "amount_exact": True,
            "amount_lte_cents": None,
            "approval_required": False,
        }
    ],
}


def _policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(POLICY))
    return path


def _argv(policy: Path, **over: str) -> list[str]:
    args = {
        "policy": str(policy),
        "amount_cents": "20000",
        "currency": "USD",
        "to": "acme-991",
        "from": "checking-881",
        "ref": "A-991",
        "now": str(NOW),
        "nonce": NONCE,
    }
    args.update(over)
    out = ["run"]
    for key, value in args.items():
        out += [f"--{key.replace('_', '-')}", value]
    return out


def test_cli_run_governed(tmp_path, capsys):
    assert main(_argv(_policy_file(tmp_path))) == 0
    out = capsys.readouterr().out
    assert out == f"EXECUTED payment=pay:000001 event=evt:{NONCE}\n"


def test_deny_explains(tmp_path, capsys):
    policy = _policy_file(tmp_path)
    assert main(_argv(policy, to="evil-999")) == 3
    out = capsys.readouterr().out
    assert out == f"DENIED reason=no rule matches event=evt:{NONCE}\n"
    assert main(_argv(policy, fund_cents="100")) == 3
    out = capsys.readouterr().out
    assert out == f"DENIED reason=denied: insufficient funds event=evt:{NONCE}\n"


def test_cli_bad_policy(tmp_path, capsys):
    assert main(_argv(tmp_path / "nope.json")) == 2
    err = capsys.readouterr().err
    assert "policy file not found" in err
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert main(_argv(bad)) == 2
    assert "invalid policy" in capsys.readouterr().err
    with pytest.raises(SystemExit) as exited:
        main(_argv(_policy_file(tmp_path), amount_cents="-5"))
    assert exited.value.code == 2


ROOT = Path(__file__).resolve().parent.parent


def test_fresh_venv_install_smoke(tmp_path):
    venv = tmp_path / "venv"
    run = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "venv", str(venv)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert run.returncode == 0, run.stderr[-2000:]
    vpy = venv / "bin" / "python"
    installed = subprocess.run(  # noqa: S603
        [str(vpy), "-m", "pip", "install", "."],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert installed.returncode == 0, installed.stderr[-2000:]
    binary = venv / "bin" / "mandate"
    assert binary.exists()
    policy = _policy_file(tmp_path)
    governed = subprocess.run(  # noqa: S603
        [str(binary), *_argv(policy)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert governed.returncode == 0, governed.stderr[-2000:]
    assert governed.stdout == f"EXECUTED payment=pay:000001 event=evt:{NONCE}\n"


@pytest.mark.parametrize("mode", [Mode.ENFORCE, Mode.SHADOW])
def test_run_result_carries_the_decided_action(keypair, mode):
    priv, pub = keypair
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = run_governed(_request(priv, mode), bank, Verifier(pub))
    assert result.action is not None
    assert result.salt is not None
    assert action_commitment(result.action, result.salt) == result.event.action_hash
    assert result.action.freshness == Freshness(NONCE, TS)


def test_the_bank_settles_the_salted_hash_the_gate_certified(keypair):
    priv, pub = keypair
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    result = run_governed(_request(priv, salt=b"\x0c" * 32), bank, Verifier(pub))
    assert result.salt == b"\x0c" * 32
    assert result.payment is not None
    assert result.payment.action_hash == result.event.action_hash == SDK_COMMITMENT
