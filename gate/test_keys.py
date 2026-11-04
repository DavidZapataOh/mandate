import pytest

from gate.keys import strict_ed25519_public_key

# Every encoding of a point of order 1, 2, 4 or 8 (libsodium's
# ge25519_has_small_order list), sign bit clear and set. Under OpenSSL each
# loads, and the signature 01 00..00 || 00..00 verifies for many messages.
SMALL_ORDER = [
    "00" * 32,
    "00" * 31 + "80",
    "01" + "00" * 31,
    "01" + "00" * 30 + "80",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ec" + "ff" * 30 + "7f",
    "ec" + "ff" * 30 + "ff",
    "ed" + "ff" * 30 + "7f",
    "ed" + "ff" * 30 + "ff",
    "ee" + "ff" * 30 + "7f",
    "ee" + "ff" * 30 + "ff",
]
# RFC 8032 section 7.1, TEST 1 public key.
RFC_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


@pytest.mark.parametrize("key", SMALL_ORDER)
def test_small_order_keys_are_refused(key):
    assert strict_ed25519_public_key(bytes.fromhex(key)) is False


def test_a_non_canonical_encoding_is_refused():
    # y = p + 2: the same y as 2, written past the field size.
    assert strict_ed25519_public_key(bytes.fromhex("ef" + "ff" * 30 + "7f")) is False


def test_a_real_key_is_accepted():
    assert strict_ed25519_public_key(bytes.fromhex(RFC_KEY)) is True


@pytest.mark.parametrize(
    "raw",
    [b"", bytes(31), bytearray.fromhex(RFC_KEY), RFC_KEY],
    ids=["empty", "short", "bytearray", "hex text"],
)
def test_only_32_raw_bytes_are_a_key(raw):
    assert strict_ed25519_public_key(raw) is False
