from handler import charge


def test_charge() -> None:
    assert charge(100) == 100
