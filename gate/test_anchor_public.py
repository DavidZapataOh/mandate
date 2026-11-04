import hashlib

from gate.conftest import OTS, unb64

ROOT = "70566024e09c9a9e301eab2459d8c10dd21d4a8b28d98cb0010cc3a8be0bde87"
DIGEST = "fe28838c6cdcfc365aef8d643ea05cd90abb7e58ffe7f60dfb57ea077fcf071a"
FOREIGN = "c46a611449cff2230732c0128a2900a35731d006b3f035119c99840ebc89d54b"
MAGIC = "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294" + "0108"
AGGREGATORS = [
    "https://a.pool.eternitywall.com",
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://ots.btc.catallaxy.com",
]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _block(header_hex: str) -> str:
    header = bytes.fromhex(header_hex)
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


def test_recorded_fixtures_are_the_published_proofs():
    core, hello, golden = OTS["core29"], OTS["hello2015"], OTS["golden"]
    assert _sha(unb64(core["pending"])) == (
        "e91f4c5104cce1b425a94fbbb918d05d9f40d8424c6b06ffebb90369f1ede1d5"
    )
    assert _sha(unb64(core["upgraded"])) == (
        "ed42bc6232526a17fe069d40e786534c53b9671639bbaaa339d90161b7ca5a84"
    )
    assert _sha(unb64(hello["proof"])) == (
        "be61ecb940db2e4a6f89fbed59c8d4f7f74fa756cbc1fad1ad7aabcb2bf59c30"
    )
    assert _block(core["headers"]["892418"]) == (
        "0000000000000000000167a45f26c2afb6a0df3009f8241a647b950a79e3da58"
    )
    assert _block(core["headers"]["892421"]) == (
        "00000000000000000000b2862b8f686909ae1715c230ed562f0b3d76e9327a24"
    )
    assert _block(hello["header"]) == (
        "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319"
    )
    assert sorted(OTS["aggregators"]) == AGGREGATORS
    assert len(core["answers"]) == 4
    assert (golden["root"], golden["digest"]) == (ROOT, DIGEST)
    assert unb64(golden["pending"]).hex().startswith(MAGIC + DIGEST + "f010")
    assert (golden["confirmed"], golden["bitcoin"]) == (None, None)
    assert OTS["foreign"]["digest"] == FOREIGN
    assert unb64(OTS["foreign"]["pending"]).hex().startswith(MAGIC + FOREIGN + "f010")
    assert unb64(OTS["bare"]["pending"]).hex().startswith(MAGIC + ROOT + "f010")
