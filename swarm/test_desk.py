import hashlib
import hmac
import json

from gate.certs import generate_keypair
from gate.consent import Consent, HolderApproval, sign_approval
from gate.registry import InclusionProof, Registry, verify_inclusion
from gate.sdjwt import process
from swarm.console_line import console_line_json
from swarm.receipt import RECEIPT_TYP, present

NOW = 1800001000
SUMMARY = "Pay 200.00 USD to acme-991 (ref A-991) from checking-881"
ZERO = HolderApproval(b"\x00" * 64, b"\x00" * 32, b"\x00" * 64)


def _quote(desk):
    return desk.quote("acme-991", 20000, "USD", "A-991")


def _root(kind, body):
    expected = Registry()
    expected.append(kind, body)
    return expected.root()


def test_quote_shape(make_desk):
    desk, _ = make_desk()
    q = _quote(desk)
    assert (q["status"], q["quote_id"], q["summary"]) == (
        "quoted",
        "q:000001",
        SUMMARY,
    )
    assert q["consent"] == {
        "amount_cents": 20000,
        "currency": "USD",
        "expires_at": NOW + 600,
        "nonce": f"{1:032x}",
        "recipient": "acme-991",
        "reference": "A-991",
        "source": "checking-881",
    }
    assert [p["quote_id"] for p in desk.pending()] == ["q:000001"]


def test_confirm_requires_approval(make_desk):
    desk, _ = make_desk()
    _quote(desk)
    assert desk.confirm("q:000001")["status"] == "quoted"
    assert desk.bank.get_balance("acme-991") == 0


def test_bad_signature_keeps_quote_open(make_desk):
    desk, _ = make_desk()
    _quote(desk)
    out = desk.approve("q:000001", ZERO)
    assert (out["status"], out["reason"]) == ("denied", "consent: bad signature")
    assert desk.status("q:000001")["status"] == "quoted"


def test_approve_then_confirm_pays(make_desk, sign_quote):
    desk, holder = make_desk()
    q = _quote(desk)
    assert desk.approve("q:000001", sign_quote(holder, q))["status"] == "approved"
    done = desk.confirm("q:000001")
    assert (done["status"], done["payment_id"], done["reason"]) == (
        "confirmed",
        "pay:000001",
        "ok: executed",
    )
    assert desk.bank.get_balance("acme-991") == 20000
    assert desk.receipt("pay:000001")["quote_id"] == "q:000001"
    body = (
        '{"payment_id":"pay:000001","quote_id":"q:000001",'
        '"reason":"ok: executed","status":"confirmed"}'
    )
    assert desk.registry.root() == _root("execution", body)


def test_confirm_twice_pays_once(make_desk, sign_quote):
    desk, holder = make_desk()
    q = _quote(desk)
    desk.approve("q:000001", sign_quote(holder, q))
    first = desk.confirm("q:000001")
    assert desk.confirm("q:000001") == first
    assert desk.bank.get_balance("acme-991") == 20000
    assert desk.registry.prove(1).leaves == 1


def test_expired_approval_denied_at_gate(make_desk, sign_quote):
    now = [NOW]
    desk, holder = make_desk(clock=lambda: now[0])
    q = _quote(desk)
    desk.approve("q:000001", sign_quote(holder, q))
    now[0] = NOW + 601
    out = desk.confirm("q:000001")
    assert (out["status"], out["reason"]) == ("denied", "consent: expired")
    assert desk.bank.get_balance("acme-991") == 0
    body = (
        '{"payment_id":null,"quote_id":"q:000001",'
        '"reason":"consent: expired","status":"denied"}'
    )
    assert desk.registry.root() == _root("denial", body)


def test_expired_quote_cannot_be_approved(make_desk, sign_quote):
    now = [NOW]
    desk, holder = make_desk(clock=lambda: now[0])
    q = _quote(desk)
    now[0] = NOW + 601
    assert desk.approve("q:000001", sign_quote(holder, q))["status"] == "expired"
    assert desk.pending() == []


def test_holder_registration_is_once(make_desk):
    desk, _ = make_desk()
    _, other = generate_keypair()
    assert desk.register_holder(other) is False
    assert other not in desk.holder_keys


def test_malformed_quote_denied(make_desk):
    desk, _ = make_desk()
    out = desk.quote("acmé", 20000, "USD", "A-991")
    assert out == {"status": "denied", "reason": "consent: malformed"}
    assert desk.pending() == []
    assert _quote(desk)["quote_id"] == "q:000001"


def test_unknown_ids(make_desk):
    desk, _ = make_desk()
    assert desk.status("q:999999") == {"status": "unknown", "quote_id": "q:999999"}
    assert desk.receipt("pay:999999") == {
        "status": "unknown",
        "payment_id": "pay:999999",
    }


def _approved(desk, holder, sign_quote, amount=20000):
    q = desk.quote("acme-991", amount, "USD", "A-991")
    desk.approve(q["quote_id"], sign_quote(holder, q))
    return q["quote_id"]


def test_returned_results_are_copies(make_desk, sign_quote):
    desk, holder = make_desk()
    qid = _approved(desk, holder, sign_quote)
    first = desk.confirm(qid)
    first["status"] = "hacked"
    desk.receipt("pay:000001")["reason"] = "x"
    desk.status(qid)["status"] = "hacked"
    assert desk.confirm(qid)["status"] == "confirmed"
    assert desk.receipt("pay:000001")["reason"] == "ok: executed"
    desk.confirm(qid)["status"] = "hacked"
    assert desk.status(qid)["status"] == "confirmed"


def test_full_registry_blocks_before_money_moves(make_desk, sign_quote):
    desk, holder = make_desk()
    desk.registry = Registry(max_entries=1)
    desk.registry.append("execution", "x")
    qid = _approved(desk, holder, sign_quote)
    out = desk.confirm(qid)
    assert out == {
        "status": "denied",
        "reason": "registry: full",
        "quote_id": qid,
    }
    assert desk.bank.get_balance("acme-991") == 0
    assert desk.status(qid)["status"] == "approved"


def test_bank_failure_denied_once(make_desk, sign_quote):
    desk, holder = make_desk()
    qid = _approved(desk, holder, sign_quote, amount=60000)
    out = desk.confirm(qid)
    assert out["status"] == "denied"
    assert out["reason"] != "ok: executed"
    assert out["payment_id"] is None
    assert desk.bank.get_balance("checking-881") == 50000
    assert desk.registry.prove(1).leaves == 1
    assert desk.confirm(qid) == out
    assert desk.registry.prove(1).leaves == 1


def test_approve_on_confirmed_changes_nothing(make_desk, sign_quote):
    desk, holder = make_desk()
    q = desk.quote("acme-991", 20000, "USD", "A-991")
    sig = sign_quote(holder, q)
    desk.approve(q["quote_id"], sig)
    done = desk.confirm(q["quote_id"])
    assert desk.approve(q["quote_id"], sig) == done
    assert desk.status(q["quote_id"]) == done


def _published(make_desk, **kwargs):
    lines = []
    desk, holder = make_desk(publish=lines.append, **kwargs)
    return desk, holder, lines


def test_desk_publishes_each_step(make_desk, sign_quote):
    desk, holder, lines = _published(make_desk)
    q = _quote(desk)
    desk.approve("q:000001", ZERO)
    desk.approve("q:000001", sign_quote(holder, q))
    desk.approve("q:000001", sign_quote(holder, q))
    desk.confirm("q:000001")
    desk.confirm("q:000001")
    desk.status("q:000001")
    assert [(x.subject["step"], x.subject["status"]) for x in lines] == [
        ("quote", "quoted"),
        ("approve", "denied"),
        ("approve", "approved"),
        ("confirm", "confirmed"),
    ]
    assert {x.subject["summary"] for x in lines} == {SUMMARY}
    assert [x.forensic is None for x in lines] == [True, True, True, False]


def test_confirm_line_carries_the_gate_run(make_desk, sign_quote):
    desk, holder, lines = _published(make_desk)
    q = _quote(desk)
    desk.approve("q:000001", sign_quote(holder, q))
    desk.confirm("q:000001")
    line = lines[-1]
    assert line.subject == {
        "step": "confirm",
        "quote_id": "q:000001",
        "status": "confirmed",
        "summary": SUMMARY,
        "payment_id": "pay:000001",
        "reason": "ok: executed",
    }
    forensic = line.forensic
    assert line.event["verdict"] == "MET"
    assert forensic["action_hash"] == line.event["action"] == CONFIRM_HASH
    assert forensic["cert_claims"]["action_hash"] == CONFIRM_HASH
    assert forensic["cert_claims"]["scope"] == "mcp:bank.pay:transfer"
    assert forensic["cava"]["targets"] == [
        "amount:USD:20000",
        "from:checking-881",
        "ref:A-991",
        "to:acme-991",
    ]
    assert forensic["cava"]["evidence_refs"] == ["q:000001"]
    assert forensic["policy"] == {"policy_id": "desk", "rule_id": "pay-with-consent"}
    assert forensic["consent"] == q["consent"]
    body = (
        '{"payment_id":"pay:000001","quote_id":"q:000001",'
        '"reason":"ok: executed","status":"confirmed"}'
    )
    proof = forensic["registry"]
    assert (proof["seq"], proof["leaves"], proof["siblings"]) == (1, 1, [])
    assert proof["root"] == _root("execution", body)
    assert verify_inclusion(
        InclusionProof(**{**proof, "siblings": ()}), _root("execution", body)
    )
    assert forensic["anchor"] is None


def test_denied_confirm_line_has_no_claims(make_desk, sign_quote):
    now = [NOW]
    desk, holder, lines = _published(make_desk, clock=lambda: now[0])
    q = _quote(desk)
    desk.approve("q:000001", sign_quote(holder, q))
    now[0] = NOW + 601
    desk.confirm("q:000001")
    line = lines[-1]
    assert (line.subject["status"], line.subject["reason"]) == (
        "denied",
        "consent: expired",
    )
    assert line.event["verdict"] == "NOT_MET"
    assert line.forensic["cert_claims"] is None
    assert line.forensic["registry"]["seq"] == 1


def test_malformed_quote_line(make_desk):
    desk, _, lines = _published(make_desk)
    desk.quote("acmé", 20000, "USD", "A-991")
    assert lines[0].subject == {
        "step": "quote",
        "quote_id": None,
        "status": "denied",
        "summary": "Pay 200.00 USD to acmé (ref A-991) from checking-881",
        "payment_id": None,
        "reason": "consent: malformed",
    }


CONFIRM_HASH = "52e9b189b7db1f410229e8bb9a3a4a99d34e30523c3507480821839a3845069b"
CONFIRM_SHA256 = "3a531d410be21c6560924338e72dee619d7117ad3e733d3087f903f8aa974d29"


def test_the_certificate_names_no_debit_account(make_desk, sign_quote):
    desk, holder, lines = _published(make_desk)
    q = _quote(desk)
    desk.approve("q:000001", sign_quote(holder, q))
    desk.confirm("q:000001")
    claims = lines[-1].forensic["cert_claims"]
    assert "checking-881" not in json.dumps(claims)
    assert desk.bank.get_balance("checking-881") == 30000


def test_a_full_guess_cannot_be_confirmed_from_the_certificate(make_desk, sign_quote):
    desk, holder, lines = _published(make_desk)
    q = _quote(desk)
    desk.approve("q:000001", sign_quote(holder, q))
    desk.confirm("q:000001")
    forensic = lines[-1].forensic
    guess = {**forensic["cava"], "targets": [
        "amount:USD:20000", "from:checking-881", "ref:A-991", "to:acme-991"
    ]}  # fmt: skip
    text = json.dumps(guess, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(text.encode("ascii")).hexdigest() == CONFIRM_SHA256
    assert forensic["cert_claims"]["action_hash"] != CONFIRM_SHA256
    keyed = hmac.new(b"\x01" * 32, text.encode("ascii"), hashlib.sha256)
    assert keyed.hexdigest() == forensic["cert_claims"]["action_hash"]
    # Whole public surface, not only the claims: the unsalted digest of the
    # full guess appears in no console line and no registry body.
    for line in lines:
        assert CONFIRM_SHA256 not in console_line_json(line)
    for entry in desk.registry._entries:
        assert CONFIRM_SHA256 not in entry.body


def test_the_desk_keeps_the_action_salt_privately(make_desk, sign_quote):
    desk, holder, lines = _published(make_desk)
    q = _quote(desk)
    desk.approve("q:000001", sign_quote(holder, q))
    result = desk.confirm("q:000001")
    pid = result["payment_id"]
    hexed = (b"\x01" * 32).hex()
    held = desk.proof_receipt(pid)
    holder_view, _ = process(held["sd"], desk.gate_public_key, RECEIPT_TYP)
    assert holder_view["cava"]["action_salt"] == hexed
    auditor = present(held, frozenset())
    auditor_view, _ = process(auditor["sd"], desk.gate_public_key, RECEIPT_TYP)
    assert "action_salt" not in auditor_view["cava"]
    assert hexed not in json.dumps(auditor)
    assert hexed not in json.dumps(desk.receipt(pid))
    assert hexed not in json.dumps(result)
    assert hexed not in repr(result)
    for line in lines:
        assert hexed not in console_line_json(line)
    for entry in desk.registry._entries:
        assert hexed not in entry.body


def test_salt_fields_stay_out_of_repr():
    from gate.shim import Decision
    from mandate.client import RunResult
    from swarm.nimbus import StepOutcome
    from swarm.redteam import AttackOutcome

    for cls in (Decision, RunResult, StepOutcome, AttackOutcome):
        salt_field = cls.__dataclass_fields__["salt"]
        assert salt_field.repr is False


def test_an_approval_for_another_quote_is_refused(make_desk, sign_quote):
    desk, holder = make_desk()
    first, second = _quote(desk), _quote(desk)
    out = desk.approve(second["quote_id"], sign_quote(holder, first))
    assert (out["status"], out["reason"]) == ("denied", "consent: bad signature")
    assert desk.status(second["quote_id"])["status"] == "quoted"


def test_a_reused_consent_key_pays_only_once(make_desk):
    desk, holder = make_desk()
    quotes = [_quote(desk), _quote(desk)]
    for q in quotes:
        unsigned = Consent(**q["consent"], signature=b"")
        desk.approve(q["quote_id"], sign_approval(holder, unsigned, b"\x81" * 32))
    first, second = (desk.confirm(q["quote_id"]) for q in quotes)
    assert first["status"] == "confirmed"
    assert (second["status"], second["reason"]) == ("denied", "consent: key reused")
    assert desk.bank.get_balance("acme-991") == 20000


def test_an_approval_reusing_a_consumed_key_leaves_the_quote_open(make_desk):
    desk, holder = make_desk()
    quotes = [_quote(desk), _quote(desk)]
    first = Consent(**quotes[0]["consent"], signature=b"")
    desk.approve(quotes[0]["quote_id"], sign_approval(holder, first, b"\x82" * 32))
    assert desk.confirm(quotes[0]["quote_id"])["status"] == "confirmed"
    stale = Consent(**quotes[1]["consent"], signature=b"")
    out = desk.approve(
        quotes[1]["quote_id"], sign_approval(holder, stale, b"\x82" * 32)
    )
    assert (out["status"], out["reason"]) == ("denied", "consent: key reused")
    assert desk.status(quotes[1]["quote_id"])["status"] == "quoted"
    fresh = sign_approval(holder, stale, b"\x83" * 32)
    assert desk.approve(quotes[1]["quote_id"], fresh)["status"] == "approved"
    assert desk.confirm(quotes[1]["quote_id"])["status"] == "confirmed"


def test_an_approval_using_the_paired_key_directly_leaves_the_quote_open(make_desk):
    desk, holder = make_desk()
    q = _quote(desk)
    unsigned = Consent(**q["consent"], signature=b"")
    out = desk.approve(q["quote_id"], sign_approval(holder, unsigned, holder))
    assert (out["status"], out["reason"]) == ("denied", "consent: key reused")
    assert desk.status(q["quote_id"])["status"] == "quoted"


def test_a_receipt_failure_keeps_the_paid_confirm(
    make_desk, sign_quote, monkeypatch, caplog
):
    def broken(*args, **kwargs):
        raise ValueError("secret-detail acme-991 A-991")

    monkeypatch.setattr("swarm.desk.proof_receipt", broken)
    desk, holder, lines = _published(make_desk)
    quote_id = _approved(desk, holder, sign_quote)
    with caplog.at_level("ERROR", logger="swarm.desk"):
        done = desk.confirm(quote_id)
    assert (done["status"], done["payment_id"]) == ("confirmed", "pay:000001")
    assert desk.bank.get_balance("acme-991") == 20000
    assert desk.proof_receipt("pay:000001") is None
    assert [x.subject["status"] for x in lines][-1] == "confirmed"
    assert [r.getMessage() for r in caplog.records] == [
        "receipt not built for pay:000001 (ValueError)"
    ]
    assert "secret-detail" not in caplog.text
    assert "acme-991" not in caplog.text
