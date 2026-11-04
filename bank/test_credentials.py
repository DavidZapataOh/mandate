import pytest

from bank.credentials import (
    BANK_KEY_ENV,
    holds_bank_key,
    take_bank_key,
    without_bank_key,
)


def test_taking_the_key_removes_it_from_the_environment():
    env = {BANK_KEY_ENV: "k1", "PATH": "/bin"}
    assert take_bank_key(env) == "k1"
    assert env == {"PATH": "/bin"}
    assert take_bank_key(env) is None


def test_an_empty_key_is_no_key():
    assert take_bank_key({BANK_KEY_ENV: ""}) is None


def test_agent_environment_never_carries_the_key():
    env = {BANK_KEY_ENV: "k1", "PATH": "/bin"}
    assert without_bank_key(env) == {"PATH": "/bin"}
    assert env[BANK_KEY_ENV] == "k1"


BANK_KEYS = ("INCREASE_SANDBOX_API_KEY", "INCREASE_HOLDER_API_KEY", "INCREASE_API_KEY")


def test_agent_environment_carries_no_increase_key_of_any_name():
    env = {name: "k" for name in BANK_KEYS} | {"PATH": "/bin"}
    assert without_bank_key(env) == {"PATH": "/bin"}


@pytest.mark.parametrize("name", BANK_KEYS)
def test_any_increase_key_name_counts_as_holding_the_key(name):
    assert holds_bank_key({name: "k", "PATH": "/bin"}) is True
    assert holds_bank_key({"PATH": "/bin"}) is False
