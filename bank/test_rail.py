import pytest

from bank.api import Bank, Payment, PaymentRequest, ReplayError
from bank.rail import bank_view, idempotency_key

REQUEST = PaymentRequest("checking-881", "acme-991", 20000, "USD", "A-991")


def test_simulated_bank_moves_once_per_key():
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    first = bank.execute(REQUEST, "h1", "mandate-cert-k1")
    with pytest.raises(ReplayError):
        bank.execute(REQUEST, "h1", "mandate-cert-k1")
    assert (first.rail, first.status, first.idempotency_key) == (
        "simulated",
        "complete",
        "mandate-cert-k1",
    )
    assert bank.get_balance("checking-881") == 30000
    assert bank.get_balance("acme-991") == 20000
    second = bank.execute(REQUEST, "h2", "mandate-cert-k2")
    assert second.payment_id == "pay:000002"


def test_simulated_bank_without_key_keeps_paying():
    bank = Bank({"checking-881": 50000, "acme-991": 0})
    bank.execute(REQUEST, "h1")
    bank.execute(REQUEST, "h1")
    assert bank.get_balance("acme-991") == 40000


def test_idempotency_key_is_the_certificate_id():
    jti = "00000000000000000000000000000002"
    assert idempotency_key(jti) == "mandate-cert-00000000000000000000000000000002"


@pytest.mark.parametrize("jti", ["", "a b", "café", "x" * 188, "a\nb"])
def test_idempotency_key_refuses_unusable_jti(jti):
    with pytest.raises(ValueError, match="jti unusable as idempotency key"):
        idempotency_key(jti)


def test_bank_view_names_rail_and_transfer():
    payment = Payment(
        "account_transfer_7k9qe1ysdgqztnt63l7n",
        "checking-881",
        "acme-991",
        20000,
        "USD",
        "A-991",
        "h1",
        rail="sandbox",
        provider="increase",
        status="complete",
        idempotency_key="mandate-cert-j1",
    )
    assert bank_view(payment) == {
        "rail": "sandbox",
        "provider": "increase",
        "transfer_id": "account_transfer_7k9qe1ysdgqztnt63l7n",
        "status": "complete",
        "idempotency_key": "mandate-cert-j1",
    }
    assert bank_view(None) is None
