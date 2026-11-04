"""Ed25519 public keys accepted from outside: canonical and not of small order."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_KEY_LEN = 32
_P = 2**255 - 19
_Y_MASK = (1 << 255) - 1
# libsodium's ge25519_has_small_order: compared over the low 31 bytes and the
# top byte without its sign bit. Under OpenSSL, R = identity and S = 0 verify
# for many messages under these keys, so no secret would be needed to sign.
_SMALL_ORDER = frozenset(
    bytes.fromhex(h)
    for h in (
        "00" * 32,
        "01" + "00" * 31,
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ec" + "ff" * 30 + "7f",
        "ed" + "ff" * 30 + "7f",
        "ee" + "ff" * 30 + "7f",
    )
)


def strict_ed25519_public_key(raw: object) -> bool:
    """True when `raw` is a canonical Ed25519 public key not of small order.

    Args:
        raw: Candidate key as received from outside.

    Returns:
        True only for 32 `bytes` whose y coordinate is below the field size,
        whose encoding is none of the small-order points (either sign), and
        which the Ed25519 implementation loads.
    """
    if type(raw) is not bytes or len(raw) != _KEY_LEN:
        return False
    if int.from_bytes(raw, "little") & _Y_MASK >= _P:
        return False
    if raw[:31] + bytes([raw[31] & 0x7F]) in _SMALL_ORDER:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        return False
    return True
