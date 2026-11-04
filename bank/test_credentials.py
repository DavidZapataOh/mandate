import pytest

from bank.credentials import (
    BANK_KEY_ENV,
    HOLDER_KEY_ENV,
    credential_exposed,
    take_bank_key,
    take_holder_key,
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
    assert credential_exposed({name: "k", "PATH": "/bin"}) is True
    assert credential_exposed({"PATH": "/bin"}) is False


def test_the_holder_key_is_taken_and_stripped_with_the_bank_key():
    env = {BANK_KEY_ENV: "k1", HOLDER_KEY_ENV: "k2", "PATH": "/bin"}
    assert without_bank_key(env) == {"PATH": "/bin"}
    assert take_holder_key(env) == "k2"
    assert env == {BANK_KEY_ENV: "k1", "PATH": "/bin"}
    assert take_holder_key({HOLDER_KEY_ENV: ""}) is None


def test_either_key_exposes_an_environment():
    assert credential_exposed({HOLDER_KEY_ENV: ""})
    assert credential_exposed({BANK_KEY_ENV: "k"})
    assert not credential_exposed({"PATH": "/bin"})
