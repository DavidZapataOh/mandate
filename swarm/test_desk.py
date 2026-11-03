from gate.certs import generate_keypair
from gate.registry import InclusionProof, Registry, verify_inclusion

NOW = 1800001000
SUMMARY = "Pay 200.00 USD to acme-991 (ref A-991) from checking-881"


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
    out = desk.approve("q:000001", b"\x00" * 64)
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
    desk.approve("q:000001", b"\x00" * 64)
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
    assert forensic["action_hash"] == line.event["action"]
    assert forensic["cert_claims"]["action_hash"] == line.event["action"]
    assert forensic["cert_claims"]["scope"] == "mcp:bank.pay:transfer:checking-881"
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
