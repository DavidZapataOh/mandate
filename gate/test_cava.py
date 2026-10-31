import dataclasses

import pytest

from bench.runner import run_bench
from gate.cava import CavaAction, Freshness, action_hash, canonical_bytes

ACTION = CavaAction(
    version="cava/1",
    runtime="mcp",
    executable="bank.pay",
    operation="transfer",
    category="payments",
    targets=(
        "acct:checking-881",
        "merchant:acme-991",
        "amount:USD:20000",
        "to:acme-991",
        "from:checking-881",
        "ref:A-991",
    ),
    reversible=False,
    freshness=Freshness(
        nonce="deadbeef00112233445566778899aabbcc", timestamp=1800000000
    ),
    evidence_refs=("ev:funds-proof-7f3a",),
)


def test_golden_bytes_and_hash():
    expected = (
        '{"category":"payments","evidence_refs":["ev:funds-proof-7f3a"],'
        '"executable":"bank.pay","freshness":{"nonce":'
        '"deadbeef00112233445566778899aabbcc","timestamp":1800000000},'
        '"operation":"transfer","reversible":false,"runtime":"mcp",'
        '"targets":["acct:checking-881","merchant:acme-991",'
        '"amount:USD:20000","to:acme-991","from:checking-881",'
        '"ref:A-991"],"version":"cava/1"}'
    )
    assert canonical_bytes(ACTION) == expected.encode("ascii")
    digest = action_hash(ACTION)
    assert digest == "5393e9fa493501ae0f5a7247bd5e8c6722b37d05996e2baab609ac920990002b"


def test_frozen_and_tuple_typed():
    with pytest.raises(dataclasses.FrozenInstanceError):
        ACTION.operation = "refund"
    assert isinstance(ACTION.targets, tuple)
    assert isinstance(ACTION.evidence_refs, tuple)


def test_rejects_bad_construction():
    with pytest.raises(ValueError):
        dataclasses.replace(ACTION, version="cava/2")
    with pytest.raises(ValueError):
        dataclasses.replace(ACTION, executable="")
    with pytest.raises(ValueError):
        dataclasses.replace(ACTION, operation="")
    with pytest.raises(ValueError):
        dataclasses.replace(ACTION, freshness=Freshness(nonce="", timestamp=1800000000))
    with pytest.raises(ValueError):
        dataclasses.replace(ACTION, freshness=Freshness(nonce="n", timestamp=-1))


def test_mutation_flips_hash():
    before = action_hash(ACTION)
    mutated = dataclasses.replace(
        ACTION,
        targets=(
            "acct:checking-881",
            "merchant:acme-991",
            "amount:USD:20001",
            "to:acme-991",
            "from:checking-881",
            "ref:A-991",
        ),
    )
    after = action_hash(mutated)
    assert after == "c05f56a25b4e3dcb06f949aac9e16134e209431833e5a47c171b1981b5710b30"
    assert before != after


def _hash_once():
    action_hash(ACTION)
    return {"hashes": 1}


def test_hash_bench_measures_real_path():
    r = run_bench("gate.cava.hash", _hash_once, n=50, warmup=5)
    assert (r.name, r.samples) == ("gate.cava.hash", 50)
    assert r.counters == {"hashes": 50}
    assert r.p50_us >= 0.0
