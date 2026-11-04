"""Selective Disclosure JWTs (RFC 9901) signed with Ed25519."""

import base64
import hashlib
import json
from collections.abc import Callable, Iterable
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SD_ALG = "sha-256"
MIN_SALT = 16


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def disclosure(salt: bytes, name: str, value: Any) -> str:
    """Object-property Disclosure (RFC 9901 §4.2.1).

    Args:
        salt: Random salt of at least 16 bytes (RFC 9901 recommends 128 bits).
        name: Claim name.
        value: JSON-serializable claim value.

    Returns:
        Unpadded base64url of the compact ASCII JSON ``[salt, name, value]``.

    Raises:
        ValueError: If ``salt`` is shorter than 16 bytes.
    """
    if len(salt) < MIN_SALT:
        raise ValueError("sd-jwt: salt under 16 bytes")
    raw = json.dumps([_b64u(salt), name, value], separators=(",", ":"))
    return _b64u(raw.encode("ascii"))


def digest(text: str) -> str:
    """Unpadded base64url SHA-256 over the ASCII Disclosure (RFC 9901 §4.2.3)."""
    return _b64u(hashlib.sha256(text.encode("ascii")).digest())


def conceal(
    obj: dict[str, Any], names: tuple[str, ...], salt: Callable[[], bytes]
) -> tuple[dict[str, Any], dict[str, str]]:
    """Replace the named claims of ``obj`` by their sorted digests.

    Args:
        obj: Claims of one JSON object.
        names: Claims to conceal; one ``salt()`` is drawn per name, in order.
        salt: Salt source.

    Returns:
        The object without the named claims and with a last ``_sd`` key, and
        each name's Disclosure.
    """
    found = {name: disclosure(salt(), name, obj[name]) for name in names}
    body = {key: value for key, value in obj.items() if key not in found}
    body["_sd"] = sorted(digest(text) for text in found.values())
    return (body, found)


def issue(payload: dict[str, Any], private_key: bytes, typ: str) -> str:
    """Issuer-signed JWT (EdDSA) over the payload with ``_sd_alg`` stated."""
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    return jwt.encode(
        {**payload, "_sd_alg": SD_ALG}, key, algorithm="EdDSA", headers={"typ": typ}
    )


def serialize(token: str, disclosures: Iterable[str]) -> str:
    """Compact SD-JWT ``<JWT>~<D.1>~...~<D.N>~`` without key binding."""
    return "".join([token, "~", *(text + "~" for text in disclosures)])


def _walk(node: Any, found: dict[str, str], used: set[str], seen: set[str]) -> Any:
    if isinstance(node, list):
        if any(isinstance(v, dict) and "..." in v for v in node):
            raise ValueError("sd-jwt: array disclosures unsupported")
        return [_walk(v, found, used, seen) for v in node]
    if not isinstance(node, dict):
        return node
    out = {k: _walk(v, found, used, seen) for k, v in node.items() if k != "_sd"}
    digests = node.get("_sd", [])
    if not isinstance(digests, list) or not all(isinstance(d, str) for d in digests):
        raise ValueError("sd-jwt: malformed")
    for d in digests:
        if d in seen:
            raise ValueError("sd-jwt: digest repeated")
        seen.add(d)
        text = found.get(d)
        if text is None:
            continue
        used.add(d)
        try:
            item = json.loads(_b64u_decode(text))
        except ValueError:
            raise ValueError("sd-jwt: disclosure malformed") from None
        if not isinstance(item, list) or len(item) != 3:
            raise ValueError("sd-jwt: disclosure malformed")
        _, name, value = item
        if not isinstance(name, str) or name in ("_sd", "...") or name in out:
            raise ValueError("sd-jwt: claim name refused")
        out[name] = _walk(value, found, used, seen)
    return out


def _verified(token: str, public_key: bytes) -> tuple[dict[str, Any] | None, str]:
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        payload: dict[str, Any] = jwt.decode(
            token,
            key,
            algorithms=["EdDSA"],
            options={"verify_exp": False, "verify_iat": False},
        )
    except jwt.InvalidSignatureError:
        return (None, "sd-jwt: bad signature")
    except (jwt.PyJWTError, ValueError):
        return (None, "sd-jwt: malformed")
    return (payload, "ok: verified")


def process(
    sd_jwt: str, public_key: bytes, typ: str
) -> tuple[dict[str, Any] | None, str]:
    """Verify a compact SD-JWT and rebuild its payload (RFC 9901 §7.1).

    Args:
        sd_jwt: ``<JWT>~<D.1>~...~<D.N>~``.
        public_key: Raw Ed25519 public key of the Issuer.
        typ: Required JWT ``typ`` header.

    Returns:
        ``(payload, "ok: verified")`` with every disclosed claim in place and
        no ``_sd``/``_sd_alg``, else ``(None, reason)``.
    """
    parts = sd_jwt.split("~")
    if len(parts) < 2 or parts[-1] or not sd_jwt.isascii():
        return (None, "sd-jwt: malformed")
    payload, reason = _verified(parts[0], public_key)
    if payload is None:
        return (None, reason)
    if jwt.get_unverified_header(parts[0]).get("typ") != typ:
        return (None, "sd-jwt: wrong type")
    if payload.get("_sd_alg", SD_ALG) != SD_ALG:
        return (None, "sd-jwt: unsupported digest")
    found: dict[str, str] = {}
    for text in parts[1:-1]:
        hashed = digest(text)
        if hashed in found:
            return (None, "sd-jwt: disclosure repeated")
        found[hashed] = text
    used: set[str] = set()
    try:
        rebuilt = _walk(payload, found, used, set())
    except ValueError as refused:
        return (None, str(refused))
    if used != found.keys():
        return (None, "sd-jwt: disclosure not referenced")
    rebuilt.pop("_sd_alg", None)
    return (rebuilt, "ok: verified")
