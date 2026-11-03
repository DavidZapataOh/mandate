import json

import pytest

from gate.certs import generate_keypair
from gate.policy import Intent
from swarm.conftest import message
from swarm.intent import (
    INTENT_FORMAT,
    INTENT_INSTRUCTIONS,
    IntentError,
    PayeeBook,
    confirmed_intent,
    draft_intent,
    intent_bytes,
    intent_hash,
    sign_intent,
)

BOOK = PayeeBook.from_json(
    {"acme corp": {"account": "acme-991", "open_invoices": ["A-991"]}}
)
SPOKEN = "Pay my Acme Corp internet bill. $200. Invoice A991."
DRAFT = {
    "amount_cents": 20000,
    "currency": "USD",
    "payee_name": "Acme Corp",
    "reference": "A991",
}

ACME = Intent(20000, "USD", "acme-991", "A-991")


def _meta(fake_meta, draft):
    return fake_meta([message(json.dumps(draft))])


def test_draft_intent_resolves_payee_and_invoice(fake_meta):
    meta = _meta(fake_meta, DRAFT)
    intent, trace = draft_intent(meta, SPOKEN, BOOK)
    assert intent == Intent(20000, "USD", "acme-991", "A-991")
    sent = meta.requests[0]
    assert (sent["model"], sent["input"]) == ("muse-spark-1.3", SPOKEN)
    assert sent["instructions"] == INTENT_INSTRUCTIONS
    assert sent["text_format"] == INTENT_FORMAT
    assert trace.response_id == "resp_1"


def test_unknown_payee_refused(fake_meta):
    meta = _meta(fake_meta, dict(DRAFT, payee_name=" Evil Corp "))
    with pytest.raises(IntentError, match="payee not in book: evil corp"):
        draft_intent(meta, SPOKEN, BOOK)


def test_reference_must_be_open_invoice(fake_meta):
    meta = _meta(fake_meta, dict(DRAFT, reference="B-17"))
    with pytest.raises(IntentError, match="reference not an open invoice: B-17"):
        draft_intent(meta, SPOKEN, BOOK)


@pytest.mark.parametrize("amount", [20000.0, "20000"])
def test_draft_rejects_non_integer_amount(fake_meta, amount):
    meta = _meta(fake_meta, dict(DRAFT, amount_cents=amount))
    with pytest.raises(IntentError, match="draft: amount_cents must be a positive"):
        draft_intent(meta, SPOKEN, BOOK)


def test_draft_rejects_extra_keys(fake_meta):
    meta = _meta(fake_meta, dict(DRAFT, account="evil-666"))
    with pytest.raises(IntentError, match="draft: malformed"):
        draft_intent(meta, SPOKEN, BOOK)


def test_empty_transcript_no_call(fake_meta):
    meta = fake_meta()
    with pytest.raises(IntentError, match="empty transcript"):
        draft_intent(meta, "   ", BOOK)
    assert meta.requests == []


def test_intent_bytes_golden():
    assert intent_bytes(ACME) == (
        b'intent/v1:{"amount_cents":20000,"currency":"USD",'
        b'"recipient":"acme-991","reference":"A-991"}'
    )


def test_intent_hash_golden():
    assert intent_hash(ACME) == (
        "a7a12d73de0370d60b0ea24041a748ee6fc4db6974cf47b3b502f2c7d52b3ed8"
    )


def test_confirmed_intent_roundtrip():
    priv, pub = generate_keypair()
    assert confirmed_intent(pub, ACME, sign_intent(priv, ACME)) == ACME


def test_confirmed_intent_rejects_mismatch():
    priv, pub = generate_keypair()
    signed_other = sign_intent(priv, Intent(20001, "USD", "acme-991", "A-991"))
    with pytest.raises(IntentError, match="bad-signature: intent not confirmed"):
        confirmed_intent(pub, ACME, signed_other)


def test_confirmed_intent_rejects_wrong_key():
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    with pytest.raises(IntentError, match="bad-signature: intent not confirmed"):
        confirmed_intent(other_pub, ACME, sign_intent(priv, ACME))


def test_confirmed_intent_rejects_malformed_inputs():
    priv, pub = generate_keypair()
    sig = sign_intent(priv, ACME)
    with pytest.raises(IntentError, match="bad-signature: intent not confirmed"):
        confirmed_intent(pub[:5], ACME, sig)
    with pytest.raises(IntentError, match="bad-signature: intent not confirmed"):
        confirmed_intent(pub, ACME, sig[:10])


@pytest.mark.parametrize(
    "raw",
    [
        {"a": {"account": "x", "open_invoices": "A-991"}},
        {"a": {"account": None, "open_invoices": ["A-1"]}},
        {"a": {"account": "", "open_invoices": ["A-1"]}},
        {"a": {"account": "x", "open_invoices": [""]}},
        {"a": "nope"},
    ],
)
def test_payee_book_rejects_malformed(raw):
    with pytest.raises(IntentError, match="payee book: malformed"):
        PayeeBook.from_json(raw)


def test_payee_book_rejects_colliding_names():
    entry = {"account": "x", "open_invoices": ["A-1"]}
    with pytest.raises(IntentError, match="payee book: duplicate payee acme corp"):
        PayeeBook.from_json({"Acme Corp": entry, "acme corp ": entry})


def test_payee_book_entries_are_frozen():
    with pytest.raises(TypeError):
        BOOK.entries["evil"] = ("x", ("y",))  # type: ignore[index]


@pytest.mark.parametrize(
    "bad",
    [
        Intent(True, "USD", "acme-991", "A-991"),  # type: ignore[arg-type]
        Intent(0, "USD", "acme-991", "A-991"),
        Intent(20000, "USD", "", "A-991"),
        Intent(20000, "", "acme-991", "A-991"),
        Intent(20000, "USD", "acme-991", ""),
    ],
)
def test_malformed_intent_is_refused(bad):
    priv, pub = generate_keypair()
    with pytest.raises(IntentError, match="intent: malformed"):
        intent_bytes(bad)
    with pytest.raises(IntentError, match="intent: malformed"):
        sign_intent(priv, bad)
    with pytest.raises(IntentError, match="intent: malformed"):
        confirmed_intent(pub, bad, b"\x00" * 64)
