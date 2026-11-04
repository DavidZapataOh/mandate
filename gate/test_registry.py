import dataclasses
import sqlite3

import pytest

from gate.certs import generate_keypair, public_key_of
from gate.registry import (
    EMPTY_ROOT,
    LogEntry,
    Registry,
    verify_anchor,
    verify_inclusion,
)
from gate.state import StateStore

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


def test_size_counts_entries():
    reg = Registry()
    assert reg.size() == 0
    reg.append("execution", '{"pay":"A-991"}')
    reg.append("denial", '{"reason":"mismatch"}')
    assert reg.size() == 2


KEY = b"\x01" * 32


def _sealed(store, bodies):
    reg = Registry(keypair=(KEY, public_key_of(KEY)), state=store)
    for n, body in enumerate(bodies, 1):
        reg.append("execution", body)
        reg.anchor(1800001000 + n)
    return reg


def test_a_registry_reopens_with_its_entries_and_seals(tmp_path):
    path = tmp_path / "state.db"
    first = _sealed(StateStore(path), ["a", "b", "c"])
    root, seals = first.root(), first.anchors()
    again = Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))
    assert (again.root(), again.anchors(), again.size()) == (root, seals, 3)
    assert again.prove(2) == first.prove(2)
    again.append("denial", "d")
    assert again.anchor(1800001009).anchor_id == "anch:000004"


def test_a_store_whose_entries_do_not_match_its_seals_is_refused(tmp_path):
    path = tmp_path / "state.db"
    _sealed(StateStore(path), ["a", "b"])
    raw = sqlite3.connect(path)
    raw.execute("UPDATE entries SET body = 'evil' WHERE seq = 1")
    raw.commit()
    raw.close()
    with pytest.raises(ValueError, match="registry entries do not match their seals"):
        Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))


def test_a_seal_signed_by_another_key_is_refused(tmp_path):
    path = tmp_path / "state.db"
    _sealed(StateStore(path), ["a"])
    other = b"\x02" * 32
    with pytest.raises(ValueError, match="^state: seal does not verify$"):
        Registry(keypair=(other, public_key_of(other)), state=StateStore(path))


@pytest.mark.parametrize(
    "edit",
    [
        "DELETE FROM entries WHERE seq = 2",
        "DELETE FROM seals WHERE seq_to = 1",
        "INSERT INTO entries (seq, kind, body) VALUES (9, 'denial', 'gap')",
    ],
)
def test_a_store_with_missing_rows_is_refused(tmp_path, edit):
    path = tmp_path / "state.db"
    _sealed(StateStore(path), ["a", "b"])
    raw = sqlite3.connect(path)
    raw.execute(edit)
    raw.commit()
    raw.close()
    with pytest.raises(ValueError, match="registry entries do not match their seals"):
        Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))


def test_an_entry_appended_before_a_crash_is_sealed_after_restart(tmp_path):
    path = tmp_path / "state.db"
    first = _sealed(StateStore(path), ["a"])
    first.append("denial", "b")
    again = Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))
    assert again.size() == 2
    seal = again.anchor(1800001009)
    assert (seal.anchor_id, seal.seq_from, seal.seq_to) == ("anch:000002", 2, 2)


def test_a_failed_seal_write_leaves_the_registry_unsealed(tmp_path):
    store = StateStore(tmp_path / "state.db")
    reg = _sealed(store, ["a"])
    reg.append("denial", "b")
    store.close()
    with pytest.raises(sqlite3.ProgrammingError):
        reg.anchor(1800001009)
    assert len(reg.anchors()) == 1


def test_entry_reads_one_entry():
    reg = Registry()
    reg.append("execution", "a")
    assert reg.entry(1) == LogEntry(1, "execution", "a")
    for seq in (0, 2):
        with pytest.raises(ValueError, match=f"^unknown seq: {seq}$"):
            reg.entry(seq)
