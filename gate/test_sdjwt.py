import base64
import json

import pytest

from gate.certs import public_key_of
from gate.sdjwt import conceal, digest, disclosure, issue, process, serialize

KEY = b"\x01" * 32
TYP = "example+sd-jwt"
SALT = b"\x01" * 16


def _salts():
    n = iter(range(1, 100))
    return lambda: bytes([next(n)]) * 16


def _token(disclosed=("family_name",)):
    body, found = conceal(
        {"given_name": "Ada", "family_name": "Lovelace", "city": "London"},
        ("family_name", "city"),
        _salts(),
    )
    token = issue({"iss": "mandate", "person": body}, KEY, TYP)
    return token, found, serialize(token, [found[k] for k in disclosed])


def test_disclosure_and_digest_follow_rfc_9901():
    text = disclosure(SALT, "family_name", "Lovelace")
    assert (
        text == "WyJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRIiwiZmFtaWx5X25hbWUiLCJMb3ZlbGFjZSJd"
    )
    rfc = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
    assert digest(rfc) == "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"


def test_compact_form_ends_with_one_tilde():
    assert serialize("h.p.s", []) == "h.p.s~"
    assert serialize("h.p.s", ["d1", "d2"]) == "h.p.s~d1~d2~"


def test_process_rebuilds_only_what_is_disclosed():
    _, _, sd = _token()
    payload, reason = process(sd, public_key_of(KEY), TYP)
    assert reason == "ok: verified"
    assert payload == {
        "iss": "mandate",
        "person": {"given_name": "Ada", "family_name": "Lovelace"},
    }


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("no trailing tilde", "sd-jwt: malformed"),
        ("other issuer", "sd-jwt: bad signature"),
        ("other type", "sd-jwt: wrong type"),
        ("repeated", "sd-jwt: disclosure repeated"),
        ("unsigned", "sd-jwt: disclosure not referenced"),
        ("reserved name", "sd-jwt: claim name refused"),
    ],
)
def test_process_refuses_what_rfc_9901_rejects(case, reason):
    token, found, sd = _token()
    key, typ = public_key_of(KEY), TYP
    if case == "no trailing tilde":
        sd = sd[:-1]
    elif case == "other issuer":
        key = public_key_of(b"\x02" * 32)
    elif case == "other type":
        typ = "secevent+jwt"
    elif case == "repeated":
        sd = serialize(token, [found["city"], found["city"]])
    elif case == "unsigned":
        sd = serialize(token, [disclosure(SALT, "city", "Paris")])
    else:
        bad = disclosure(SALT, "_sd", [])
        signed = issue({"person": {"_sd": [digest(bad)]}}, KEY, TYP)
        sd = serialize(signed, [bad])
    assert process(sd, key, typ) == (None, reason)


def test_a_digest_listed_twice_is_refused():
    text = disclosure(SALT, "city", "London")
    signed = issue(
        {"a": {"_sd": [digest(text)]}, "b": {"_sd": [digest(text)]}}, KEY, TYP
    )
    assert process(serialize(signed, [text]), public_key_of(KEY), TYP) == (
        None,
        "sd-jwt: digest repeated",
    )


def test_issuer_payload_names_the_digest_algorithm():
    token, _, _ = _token()
    body = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    assert body["_sd_alg"] == "sha-256"
    assert body["person"]["_sd"] == sorted(body["person"]["_sd"])


@pytest.mark.parametrize("size", [0, 8, 15])
def test_disclosure_refuses_a_salt_under_16_bytes(size):
    with pytest.raises(ValueError, match="sd-jwt: salt under 16 bytes"):
        disclosure(b"\x01" * size, "city", "London")


def test_conceal_refuses_a_short_salt_source():
    with pytest.raises(ValueError, match="sd-jwt: salt under 16 bytes"):
        conceal({"city": "London"}, ("city",), lambda: b"\x01" * 8)
