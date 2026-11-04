import base64
import json
from pathlib import Path

import pytest

from gate.cava import CavaAction, Freshness, action_commitment
from gate.certs import public_key_of, read_claims
from gate.consent import Consent, verify_signature
from gate.registry import (
    Anchor,
    InclusionProof,
    LogEntry,
    verify_anchor,
    verify_inclusion,
)
from gate.sdjwt import process
from swarm.anchor import ReasoningAnchor
from swarm.desk import DESK_POLICY
from swarm.receipt import RECEIPT_TYP, present, proof_receipt

FIXTURES = Path(__file__).resolve().parent.parent / "console/src/explorer/__fixtures__"
GOLDEN = FIXTURES / "receipt.json"
AUDITOR = FIXTURES / "auditor.json"
GATE = b"\x01" * 32
HOLDER = b"\x02" * 32
NOW = 1800001000
PAY = ("amount:USD:20000", "from:checking-881", "ref:A-991", "to:acme-991")
UNSIGNED = Consent(20000, "USD", "acme-991", "A-991", "checking-881", "n", 1, b"")
PROOF = InclusionProof(1, 1, "00" * 32, (), "00" * 32)
SEAL = Anchor(1, "anch:000001", 1, 1, "00" * 32, 0, b"")
SALT = b"\x09" * 16
CERT = json.loads(GOLDEN.read_text())["certificate"]


def _pay(desk, sign, recipient, cents, ref):
    q = desk.quote(recipient, cents, "USD", ref)
    desk.approve(q["quote_id"], sign(HOLDER, q))
    return desk.confirm(q["quote_id"])


def _anchor(view):
    return Anchor(**{**view, "signature": base64.b64decode(view["signature"])})


def _action(executable, operation, targets):
    return CavaAction(
        "cava/1", "mcp", executable, operation, "payments", targets, False,
        Freshness("n", 0), (),
    )  # fmt: skip


def test_desk_receipt_is_the_golden(make_desk, sign_quote):
    desk, _ = make_desk(gate_key=GATE, holder_key=HOLDER)
    done = _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    receipt = desk.proof_receipt(done["payment_id"])
    assert json.dumps(receipt, separators=(",", ":")) + "\n" == GOLDEN.read_text()


def test_golden_verifies_with_the_python_verifiers():
    r = json.loads(GOLDEN.read_text())
    gate_pub = public_key_of(GATE)
    claims, reason = read_claims(r["certificate"], gate_pub)
    disclosed, sd_reason = process(r["sd"], gate_pub, RECEIPT_TYP)
    assert sd_reason == "ok: verified"
    cava = disclosed["cava"]
    plain = {k: v for k, v in cava.items() if k != "action_salt"}
    action = CavaAction(
        **{
            **plain,
            "targets": tuple(plain["targets"]),
            "freshness": Freshness(**plain["freshness"]),
            "evidence_refs": tuple(plain["evidence_refs"]),
        }
    )
    c = disclosed["consent"]
    encoded = ("signature", "holder_key", "consent_key", "key_signature")
    consent = Consent(
        **{k: v for k, v in c.items() if k not in encoded},
        signature=base64.b64decode(c["signature"]),
        consent_key=base64.b64decode(c["consent_key"]),
        key_signature=base64.b64decode(c["key_signature"]),
    )
    proof = r["registry"]["proof"]
    seal = _anchor(r["registry"]["seal"])
    salt = bytes.fromhex(cava["action_salt"])
    assert (reason, action_commitment(action, salt)) == (
        "ok: decoded",
        claims["action_hash"],
    )
    assert c["consent_key"] != c["holder_key"]
    assert verify_signature(consent, (base64.b64decode(c["holder_key"]),))
    assert verify_inclusion(
        InclusionProof(**{**proof, "siblings": tuple(proof["siblings"])}), seal.root
    )
    assert verify_anchor(seal, gate_pub)


def test_every_confirm_is_sealed(make_desk, sign_quote):
    desk, _ = make_desk(gate_key=GATE, holder_key=HOLDER)
    _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    done = _pay(desk, sign_quote, "acme-991", 300, "A-993")
    receipt = desk.proof_receipt(done["payment_id"])
    seals = desk.registry.anchors()
    proof = receipt["registry"]["proof"]
    assert [(s.seq_from, s.seq_to) for s in seals] == [(1, 1), (2, 2)]
    assert (proof["seq"], proof["leaves"], len(proof["siblings"])) == (2, 2, 1)
    assert proof["root"] == receipt["registry"]["seal"]["root"] == seals[1].root
    assert desk.latest_seal() == receipt["registry"]["seal"]


def test_a_denied_confirm_is_sealed_without_a_receipt(make_desk, sign_quote):
    now = [NOW]
    desk, holder = make_desk(clock=lambda: now[0])
    assert desk.latest_seal() is None
    q = desk.quote("acme-991", 20000, "USD", "A-991")
    desk.approve(q["quote_id"], sign_quote(holder, q))
    now[0] = NOW + 601
    assert desk.confirm(q["quote_id"])["status"] == "denied"
    assert desk.proof_receipt("pay:000001") is None
    assert desk.latest_seal()["seq_to"] == 1
    assert verify_anchor(_anchor(desk.latest_seal()), desk.gate_public_key)


def test_receipt_is_a_copy(make_desk, sign_quote):
    desk, _ = make_desk(gate_key=GATE, holder_key=HOLDER)
    done = _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    desk.proof_receipt(done["payment_id"])["registry"]["proof"]["siblings"].append("x")
    assert desk.proof_receipt(done["payment_id"])["registry"]["proof"]["siblings"] == []


def test_receipt_carries_the_reasoning_anchor():
    anchor = ReasoningAnchor(1, "muse-spark-1.3", "resp_golden_1", ("b1", "b2"))
    built = proof_receipt(
        "pay:000001", CERT, _action("bank.pay", "transfer", PAY), DESK_POLICY,
        UNSIGNED, b"k", LogEntry(1, "execution", "{}"), PROOF, SEAL, GATE,
        lambda: SALT, anchor, action_salt=b"\x01" * 32,
    )  # fmt: skip
    assert built["reasoning"] == {
        "blobs": ["b1", "b2"],
        "model": "muse-spark-1.3",
        "response_id": "resp_golden_1",
        "v": 1,
    }


def test_receipt_needs_a_matching_rule():
    with pytest.raises(ValueError, match="receipt: no matching rule"):
        proof_receipt(
            "pay:000001", CERT, _action("shell", "exec", ()), DESK_POLICY,
            UNSIGNED, b"k", LogEntry(1, "execution", "{}"), PROOF, SEAL, GATE,
            lambda: SALT, action_salt=b"\x01" * 32,
        )  # fmt: skip


@pytest.mark.parametrize("size", [0, 16, 31, 33])
def test_receipt_needs_a_32_byte_action_salt(size):
    with pytest.raises(ValueError, match="receipt: action salt must be 32 bytes"):
        proof_receipt(
            "pay:000001", CERT, _action("bank.pay", "transfer", PAY), DESK_POLICY,
            UNSIGNED, b"k", LogEntry(1, "execution", "{}"), PROOF, SEAL, GATE,
            lambda: SALT, action_salt=b"\x01" * size,
        )  # fmt: skip


def test_receipt_refuses_short_disclosure_salts():
    with pytest.raises(ValueError, match="sd-jwt: salt under 16 bytes"):
        proof_receipt(
            "pay:000001", CERT, _action("bank.pay", "transfer", PAY), DESK_POLICY,
            UNSIGNED, b"k", LogEntry(1, "execution", "{}"), PROOF, SEAL, GATE,
            lambda: b"\x02" * 8, action_salt=b"\x01" * 32,
        )  # fmt: skip


def test_auditor_copy_is_the_golden():
    full = json.loads(GOLDEN.read_text())
    text = json.dumps(present(full, frozenset()), separators=(",", ":")) + "\n"
    assert text == AUDITOR.read_text()


def _names(receipt):
    _, *texts, _ = receipt["sd"].split("~")
    return [json.loads(base64.urlsafe_b64decode(t + "==="))[1] for t in texts]


def test_present_keeps_only_the_revealed_groups():
    full = json.loads(GOLDEN.read_text())
    assert _names(present(full, frozenset({"amount"}))) == ["amount_cents", "currency"]
    assert _names(present(full, frozenset({"amount", "payee"}))) == [
        "amount_cents",
        "currency",
        "recipient",
    ]
    assert _names(present(full, frozenset({"account"}))) == ["source"]
    holder = frozenset({"holder"})
    assert _names(present(full, holder)) == ["holder_key", "key_signature"]
    every = frozenset({"amount", "payee", "account", "reference", "holder"})
    assert _names(present(full, every - {"holder"})) == [
        "targets",
        "action_salt",
        "amount_cents",
        "currency",
        "recipient",
        "reference",
        "source",
        "signature",
    ]
    assert present(full, every) == full


def test_present_refuses_an_unknown_group():
    with pytest.raises(ValueError, match="receipt: unknown group debit"):
        present(json.loads(GOLDEN.read_text()), frozenset({"debit"}))


def test_the_auditor_copy_names_no_payee_amount_reference_or_account():
    text = AUDITOR.read_text()
    secrets = ("acme-991", "A-991", "20000", "checking-881", "01" * 32)
    signatures = ("OORzeXDe6eaiUsW4PdqrQ", "Y9mn3uyjzxkfa7dU2VaN")
    paired = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q="
    for secret in (*secrets, *signatures, paired):
        assert secret not in text


def test_two_receipts_of_one_holder_share_no_key(make_desk, sign_quote):
    desk, _ = make_desk(gate_key=GATE, holder_key=HOLDER)
    paired = base64.b64encode(public_key_of(HOLDER)).decode()
    keys = []
    for ref in ("A-991", "A-993"):
        done = _pay(desk, sign_quote, "acme-991", 20000, ref)
        copy = present(desk.proof_receipt(done["payment_id"]), frozenset())
        disclosed, reason = process(copy["sd"], desk.gate_public_key, RECEIPT_TYP)
        assert reason == "ok: verified"
        assert paired not in json.dumps(disclosed)
        keys.append(disclosed["consent"]["consent_key"])
    assert keys[0] != keys[1]


def test_receipt_carries_no_secret(make_desk, sign_quote):
    desk, _ = make_desk(gate_key=GATE, holder_key=HOLDER)
    done = _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    text = json.dumps(desk.proof_receipt(done["payment_id"]))
    for private in (GATE, HOLDER):
        assert base64.b64encode(private).decode() not in text
        assert private.hex() not in text


def test_receipt_names_only_its_own_payment(make_desk, sign_quote):
    desk, _ = make_desk(gate_key=GATE, holder_key=HOLDER)
    _pay(desk, sign_quote, "acme-991", 20000, "A-991")
    done = _pay(desk, sign_quote, "acme-991", 300, "A-993")
    text = json.dumps(desk.proof_receipt(done["payment_id"]))
    assert "A-991" not in text
    assert "pay:000001" not in text
