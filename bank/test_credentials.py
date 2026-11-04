from bank.credentials import BANK_KEY_ENV, take_bank_key, without_bank_key


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
