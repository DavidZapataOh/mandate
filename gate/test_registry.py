import dataclasses

import pytest

from gate.certs import generate_keypair
from gate.registry import EMPTY_ROOT, Registry, verify_anchor, verify_inclusion

ROOT2 = "4c73721e4d564032af7dfbdae6dc57d6f1eac3f36ea892a625c3c8b53d928b31"
ROOT3 = "4f141be3d2b397f2e51da35902f9e930a485d8c34947079d22b3ff9fd97cd00f"


def test_inclusion_verifies():
    reg = Registry()
    assert reg.root() == EMPTY_ROOT
    assert reg.append("execution", '{"pay":"A-991"}') == 1
    assert reg.append("denial", '{"reason":"mismatch"}') == 2
    assert reg.root() == ROOT2
    proof = reg.prove(2)
    assert (proof.seq, proof.leaves, proof.root) == (2, 2, ROOT2)
    assert verify_inclusion(proof, ROOT2) is True
    assert verify_inclusion(proof, EMPTY_ROOT) is False
    reg.append("execution", '{"pay":"A-992"}')
    assert reg.root() == ROOT3
    assert verify_inclusion(reg.prove(1), reg.root()) is True
    with pytest.raises(ValueError, match="unknown seq: 9"):
        reg.prove(9)


def test_registry_budget():
    reg = Registry(max_entries=2)
    reg.append("execution", "a")
    reg.append("execution", "b")
    before = reg.root()
    with pytest.raises(ValueError, match="registry full"):
        reg.append("execution", "c")
    assert reg.root() == before
    with pytest.raises(ValueError, match="unknown entry kind"):
        Registry().append("gossip", "x")
    with pytest.raises(ValueError, match="entry body must be non-empty"):
        Registry().append("execution", "")


def test_hostile_inputs_deny():
    reg = Registry()
    reg.append("execution", "a")
    reg.append("denial", "b")
    root = reg.root()
    proof = reg.prove(1)
    for hostile in (
        dataclasses.replace(proof, seq="1"),
        dataclasses.replace(proof, seq=None),
        dataclasses.replace(proof, leaves="2"),
        dataclasses.replace(proof, leaves=None),
    ):
        assert verify_inclusion(hostile, root) is False
    with pytest.raises(ValueError, match="unknown entry kind"):
        reg.append([], "x")
    padded = dataclasses.replace(proof, leaf=f"  {proof.leaf}  ")
    assert verify_inclusion(padded, root) is False


def test_tamper_detected():
    honest = Registry()
    honest.append("execution", '{"pay":"A-991"}')
    honest.append("denial", '{"reason":"mismatch"}')
    forged = Registry()
    forged.append("execution", '{"pay":"A-991"}')
    forged.append("denial", '{"reason":"approved"}')
    assert honest.root() != forged.root()
    proof = honest.prove(2)
    assert verify_inclusion(proof, forged.root()) is False
    flipped = dataclasses.replace(proof, leaf="00" * 32)
    assert verify_inclusion(flipped, honest.root()) is False
    evil_sib = ("ff" * 32,) + proof.siblings[1:]
    assert (
        verify_inclusion(dataclasses.replace(proof, siblings=evil_sib), honest.root())
        is False
    )
    assert verify_inclusion(proof, "11" * 32) is False
    assert verify_inclusion(dataclasses.replace(proof, seq=99), honest.root()) is False
    assert (
        verify_inclusion(dataclasses.replace(proof, leaf="zz"), honest.root()) is False
    )


def test_anchor_referenced():
    priv, pub = generate_keypair()
    reg = Registry(keypair=(priv, pub))
    reg.append("execution", '{"pay":"A-991"}')
    reg.append("denial", '{"reason":"mismatch"}')
    anchor = reg.anchor(1800000200)
    assert anchor.v == 1
    assert anchor.anchor_id == "anch:000002"
    assert (anchor.seq_from, anchor.seq_to) == (1, 2)
    assert anchor.root == ROOT2
    assert anchor.ts == 1800000200
    assert verify_anchor(anchor, pub) is True
    assert verify_anchor(dataclasses.replace(anchor, root="11" * 32), pub) is False
    _, wrong_pub = generate_keypair()
    assert verify_anchor(anchor, wrong_pub) is False
    proof = reg.prove(1)
    assert proof.root == anchor.root
    assert verify_inclusion(proof, anchor.root) is True
    reg.append("execution", '{"pay":"A-992"}')
    second = reg.anchor(1800000300)
    assert (second.anchor_id, second.seq_from, second.seq_to) == (
        "anch:000003",
        3,
        3,
    )
    assert reg.anchors() == (anchor, second)
    with pytest.raises(ValueError, match="nothing to anchor"):
        reg.anchor(1800000400)
    with pytest.raises(ValueError, match="no keypair"):
        Registry().anchor(1800000400)


def test_registry_accepts_anchor_entries():
    registry = Registry()
    assert registry.append("anchor", '{"v":1}') == 1
    assert verify_inclusion(registry.prove(1), registry.root()) is True
    with pytest.raises(ValueError, match="unknown entry kind"):
        registry.append("bogus", "x")


def test_has_room_tracks_budget():
    reg = Registry(max_entries=1)
    assert reg.has_room() is True
    reg.append("execution", "a")
    assert reg.has_room() is False
