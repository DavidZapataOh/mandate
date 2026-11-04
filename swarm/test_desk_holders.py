import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gate.certs import generate_keypair, public_key_of
from gate.consent import Consent, sign_approval
from gate.policy import Intent
from swarm.console_line import console_line_json
from swarm.holders import unpair_bytes
from swarm.intent import sign_intent

SECOND = b"\x03" * 32
THIRD = b"\x04" * 32
ACME = Intent(20000, "USD", "acme-991", "A-991")


def _quote(desk, reference="A-991"):
    return desk.quote("acme-991", 20000, "USD", reference)


def _two(make_desk, **kwargs):
    desk, first = make_desk(**kwargs)
    assert desk.register_holder(public_key_of(SECOND)) == "h:0000000000000002"
    return desk, first


def _unpair_signature(private_key):
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    return key.sign(unpair_bytes(public_key_of(private_key)))


def test_each_paired_holder_approves_and_pays(make_desk, sign_quote):
    desk, first = _two(make_desk)
    a, b = _quote(desk, "A-991"), _quote(desk, "B-204")
    assert desk.approve(a["quote_id"], sign_quote(first, a))["status"] == "approved"
    assert desk.approve(b["quote_id"], sign_quote(SECOND, b))["status"] == "approved"
    assert [desk.confirm(q["quote_id"])["status"] for q in (a, b)] == [
        "confirmed",
        "confirmed",
    ]
    assert desk.bank.get_balance("acme-991") == 40000


def test_a_key_that_is_not_paired_cannot_approve(make_desk, sign_quote):
    desk, _ = _two(make_desk)
    q = _quote(desk)
    out = desk.approve(q["quote_id"], sign_quote(THIRD, q))
    assert (out["status"], out["reason"]) == ("denied", "consent: bad signature")
    assert desk.status(q["quote_id"])["status"] == "quoted"


def test_a_payment_pays_only_while_its_approver_is_paired(make_desk, sign_quote):
    desk, first = _two(make_desk)
    a, b = _quote(desk, "A-991"), _quote(desk, "B-204")
    desk.approve(a["quote_id"], sign_quote(first, a))
    desk.approve(b["quote_id"], sign_quote(SECOND, b))
    assert desk.unpair_holder("h:0000000000000002") is True
    assert desk.confirm(a["quote_id"])["status"] == "confirmed"
    assert desk.confirm(b["quote_id"]) == {
        "status": "denied",
        "quote_id": "q:000002",
        "reason": "holder: unpaired",
        "payment_id": None,
    }
    assert desk.bank.get_balance("acme-991") == 20000
    assert desk.registry.size() == 2


def test_an_unpaired_holder_cannot_approve_again(make_desk, sign_quote):
    desk, _ = _two(make_desk)
    desk.unpair_holder("h:0000000000000002")
    q = _quote(desk)
    out = desk.approve(q["quote_id"], sign_quote(SECOND, q))
    assert (out["status"], out["reason"]) == ("denied", "consent: bad signature")


def test_a_payment_needs_its_own_approver_not_any_paired_holder(make_desk, sign_quote):
    desk, first = _two(make_desk)
    q = _quote(desk)
    desk.approve(q["quote_id"], sign_quote(first, q))
    desk.unpair_holder("h:0000000000000001")
    assert desk.register_holder(public_key_of(THIRD)) == "h:0000000000000003"
    assert desk.confirm(q["quote_id"])["reason"] == "holder: unpaired"


def test_a_device_unpairs_itself_and_its_key_is_retired(make_desk):
    desk, _ = _two(make_desk)
    second = public_key_of(SECOND)
    assert desk.unpair_device(second, b"\x00" * 64) is False
    assert desk.unpair_device(second, _unpair_signature(THIRD)) is False
    assert desk.holder_keys == (desk.holder_keys[0], second)
    assert desk.unpair_device(second, _unpair_signature(SECOND)) is True
    assert desk.unpair_device(second, _unpair_signature(SECOND)) is False
    assert second not in desk.holder_keys
    assert desk.all_holder_keys[1] == second
    assert desk.register_holder(second) is None


def test_a_refused_unpair_key_of_the_wrong_size_raises_nothing(make_desk):
    desk, _ = make_desk()
    assert desk.unpair_device(b"\x01" * 31, b"\x00" * 64) is False


def test_desk_lines_name_no_holder(make_desk):
    lines = []
    desk, first = _two(make_desk, publish=lines.append)
    q = _quote(desk)
    unsigned = Consent(**q["consent"], signature=b"")
    desk.approve(q["quote_id"], sign_approval(SECOND, unsigned, b"\x81" * 32))
    desk.unpair_holder("h:0000000000000002")
    desk.confirm(q["quote_id"])
    text = "\n".join(console_line_json(x) for x in lines)
    assert [x.subject["step"] for x in lines] == ["quote", "approve", "confirm"]
    assert lines[-1].event is None and lines[-1].forensic is None
    assert "h:000000000000000" not in text
    for key in desk.all_holder_keys:
        assert base64.b64encode(key).decode() not in text


def test_pairing_more_holders_than_the_bound_is_refused(make_desk):
    desk, _ = make_desk()
    keys = [generate_keypair()[1] for _ in range(16)]
    ids = [desk.register_holder(k) for k in keys]
    assert ids.count(None) == 1
    assert len(desk.holder_keys) == 16


def test_an_intent_binds_its_quote_to_the_holder_who_signed_it(make_desk, sign_quote):
    desk, first = _two(make_desk)
    assert desk.record_intent(ACME, sign_intent(SECOND, ACME))["status"] == "signed"
    q = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    refused = desk.approve(q["quote_id"], sign_quote(first, q))
    assert (refused["status"], refused["reason"]) == (
        "denied",
        "consent: bad signature",
    )
    assert desk.approve(q["quote_id"], sign_quote(SECOND, q))["status"] == "approved"
    assert desk.confirm(q["quote_id"])["status"] == "confirmed"


def test_an_intent_signed_by_a_key_that_is_not_paired_is_refused(make_desk):
    desk, _ = _two(make_desk)
    assert desk.record_intent(ACME, sign_intent(THIRD, ACME)) == {
        "status": "denied",
        "reason": "intent: bad signature",
    }


def test_the_intent_of_an_unpaired_holder_cannot_be_approved(make_desk, sign_quote):
    desk, _ = _two(make_desk)
    desk.record_intent(ACME, sign_intent(SECOND, ACME))
    desk.unpair_holder("h:0000000000000002")
    q = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    out = desk.approve(q["quote_id"], sign_quote(SECOND, q))
    assert (out["status"], out["reason"]) == ("denied", "consent: bad signature")


def test_a_bound_quote_names_only_its_holder_as_approver(make_desk):
    desk, first = _two(make_desk)
    open_quote = _quote(desk, "A-992")
    desk.record_intent(ACME, sign_intent(SECOND, ACME))
    bound = desk.quote("acme-991", 20000, "USD", "A-991", intent_id="i:000001")
    assert desk.approver_keys(bound["quote_id"]) == (public_key_of(SECOND),)
    assert desk.approver_keys(open_quote["quote_id"]) == (
        public_key_of(first),
        public_key_of(SECOND),
    )
    assert desk.unpair_holder("h:0000000000000002") is True
    assert desk.approver_keys(bound["quote_id"]) == ()
    assert desk.approver_keys("q:000009") == ()
