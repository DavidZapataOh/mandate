import pytest

from bank.reconcile import BankTransfer, Reconciliation, compare


def _t(transfer_id, key, status="complete"):
    return BankTransfer(transfer_id, 20000, status, key, "2027-01-15T08:20:00Z")


SEALED = {"t1": ("j1", True), "t2": ("j2", True)}


def test_every_certified_and_sealed_transfer_reconciles():
    listed = [_t("t1", "mandate-cert-j1"), _t("t2", "mandate-cert-j2")]
    assert compare(listed, SEALED, "sandbox") == (2, (), ())


@pytest.mark.parametrize(
    ("transfer", "why"),
    [
        (_t("t9", None), "no key"),
        (_t("t9", "payroll-2027-01"), "a key that names no certificate"),
        (_t("t1", "mandate-cert-j2"), "a key naming another certificate"),
    ],
)
def test_a_transfer_no_certificate_explains_is_unbacked(transfer, why):
    certified, unbacked, _ = compare([transfer], {"t1": ("j1", True)}, "sandbox")
    assert (certified, unbacked) == (0, (transfer.transfer_id,)), why


def test_a_receipt_whose_entry_is_not_the_registrys_is_unbacked():
    listed = [_t("t1", "mandate-cert-j1")]
    assert compare(listed, {"t1": ("j1", False)}, "sandbox") == (0, ("t1",), ())


def test_a_sealed_payment_the_bank_does_not_list_is_missing():
    listed = [_t("t1", "mandate-cert-j1")]
    assert compare(listed, SEALED, "sandbox") == (1, (), ("t2",))


def test_a_canceled_transfer_moved_nothing_and_is_skipped():
    listed = [_t("t1", "mandate-cert-j1"), _t("t8", None, status="canceled")]
    assert compare(listed, {"t1": ("j1", True)}, "sandbox") == (1, (), ())


def test_the_view_has_the_pinned_keys_in_order():
    view = Reconciliation(
        "sandbox", "increase", "2027-01-15T08:16:40Z", 1800001200, 2, 2, (), (),
        ("q:000003 -> t3",), (), None,
    ).view()  # fmt: skip
    assert list(view) == [
        "rail", "provider", "since", "checked_at", "transfers", "certified",
        "unbacked", "missing", "resolved", "pending", "error",
    ]  # fmt: skip
    assert view["resolved"] == ["q:000003 -> t3"]
