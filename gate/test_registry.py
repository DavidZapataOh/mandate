import dataclasses
import hashlib
import json
import random
import sqlite3
import statistics
import time
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gate import registry as registry_module
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


def test_a_store_with_entries_past_the_last_seal_is_refused(tmp_path):
    path = tmp_path / "state.db"
    first = _sealed(StateStore(path), ["a"])
    first.append("denial", "b")
    with pytest.raises(
        ValueError, match="^state: registry entries past the last seal$"
    ):
        Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))


def test_a_store_with_entries_and_no_seal_is_refused(tmp_path):
    path = tmp_path / "state.db"
    Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path)).append(
        "denial", "a"
    )
    with pytest.raises(
        ValueError, match="^state: registry entries past the last seal$"
    ):
        Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))


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


# Independent derivation (explicit trees over leaf/v1 and node/v1, entries
# kind "denial" with bodies e1..e5).
ROOTS = (
    "55badc678ea7303e0b29620bafd3a5272651f9f93f34c749defa1124524903eb",
    "d74535584eea43632937b5ec878911f55ea58b9b2286d4f3102d75379342b8fa",
    "799e703ee77eba48594dbca6d7e3f75dcd90e35cdfa70ee537cc26a4fd42449f",
    "62c57f37bc1f47da8a8f545451e776e9f444d30d69fa1d5db81f6cee8e8d6b67",
    "8bb3b919fdcb95629200952e6cf5a8cd21370f64b0bbc9007091c88fff9e1bdd",
)
SEALED = 512


def test_each_prefix_keeps_its_root():
    reg = Registry()
    roots = []
    for n in range(1, 6):
        reg.append("denial", f"e{n}")
        roots.append(reg.root())
    assert tuple(roots) == ROOTS


def test_a_store_sealed_in_batches_reloads_and_still_refuses_an_edit(tmp_path):
    path = tmp_path / "state.db"
    reg = Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))
    for n in range(1, 9):
        reg.append("denial", f"e{n}")
        if n in (3, 5, 8):
            reg.anchor(1800001000 + n)
    again = Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))
    assert (again.root(), again.anchors()) == (reg.root(), reg.anchors())
    raw = sqlite3.connect(path)
    raw.execute("UPDATE entries SET body = 'evil' WHERE seq = 4")
    raw.commit()
    raw.close()
    with pytest.raises(ValueError, match="registry entries do not match their seals"):
        Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))


def _counting(monkeypatch):
    calls = {"leaf": 0, "node": 0}
    leaf, node = registry_module._leaf_hash, registry_module._node_hash

    def counted_leaf(entry):
        calls["leaf"] += 1
        return leaf(entry)

    def counted_node(left, right):
        calls["node"] += 1
        return node(left, right)

    monkeypatch.setattr(registry_module, "_leaf_hash", counted_leaf)
    monkeypatch.setattr(registry_module, "_node_hash", counted_node)
    return calls


def test_sealing_and_reloading_hash_each_entry_once(tmp_path, monkeypatch):
    calls = _counting(monkeypatch)
    path = tmp_path / "state.db"
    store = StateStore(path)
    with store.transaction():
        _sealed(store, [f"e{n}" for n in range(1, SEALED + 1)])
    sealing = dict(calls)
    calls.update(leaf=0, node=0)
    store.close()
    Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))
    assert (sealing["leaf"], calls["leaf"]) == (SEALED, SEALED)
    assert max(sealing["node"], calls["node"]) <= 16 * SEALED


def _ref_leaf(seq, kind, body):
    payload = json.dumps(
        {"body": body, "kind": kind, "seq": seq},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(b"leaf/v1:" + payload).digest()


def _ref_node(left, right):
    return hashlib.sha256(b"node/v1:" + left + right).digest()


def _ref_levels(leaves):
    """The whole tree, rebuilt from the leaves; the odd node out is duplicated."""
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        level = levels[-1] + levels[-1][-1:] * (len(levels[-1]) % 2)
        levels.append([_ref_node(*level[i : i + 2]) for i in range(0, len(level), 2)])
    return levels


def _ref_siblings(levels, index):
    out = []
    for level in levels[:-1]:
        padded = level + level[-1:] * (len(level) % 2)
        out.append(padded[index ^ 1].hex())
        index //= 2
    return tuple(out)


def test_roots_and_proofs_match_a_full_rebuild():
    rng = random.Random(6962)  # noqa: S311 (test data, not a secret)
    kinds = ["denial", "execution", "settlement", "return"]
    reg, leaves = Registry(), []
    assert reg.root() == EMPTY_ROOT
    with pytest.raises(ValueError, match="unknown seq"):
        reg.prove(1)
    for size in range(1, 301):
        kind, body = rng.choice(kinds), f"b{rng.randrange(10**6)}"
        reg.append(kind, body)
        leaves.append(_ref_leaf(size, kind, body))
        levels = _ref_levels(leaves)
        assert reg.root() == levels[-1][0].hex(), size
        for seq in {1, size, rng.randrange(1, size + 1)}:
            proof = reg.prove(seq)
            assert (proof.seq, proof.leaves) == (seq, size)
            assert proof.leaf == leaves[seq - 1].hex()
            assert proof.siblings == _ref_siblings(levels, seq - 1), (size, seq)
            assert verify_inclusion(proof, reg.root())


# Independent derivation over explicit trees (bodies e1..e5, kind "denial").
SIBLINGS = {
    5: (
        "9e043ba51bcf9b7033a33dd37426f1d1b0565d871b87871591c860ab5e68dcb2",
        "bf0088f9e85bb652563a2d29748cecf01391e59e0466617e75ee3dcf9b73791c",
        "62c57f37bc1f47da8a8f545451e776e9f444d30d69fa1d5db81f6cee8e8d6b67",
    ),
    3: (
        "8218fdbec666bd542e95d5ba4ca5aa61960f840a76d41904ba8a73bd7c17711a",
        "d74535584eea43632937b5ec878911f55ea58b9b2286d4f3102d75379342b8fa",
        "85a241c0a6d91eb07286638b3eb6ae70f1542cb9e1494920b2836ad5e6cc5fc0",
    ),
}


def test_proofs_keep_their_siblings():
    reg = Registry()
    for n in range(1, 6):
        reg.append("denial", f"e{n}")
    assert {seq: reg.prove(seq).siblings for seq in SIBLINGS} == SIBLINGS


def test_a_proof_costs_log_n_hashes(monkeypatch):
    reg = Registry()
    for n in range(4101):
        reg.append("denial", f"e{n}")
    calls = _counting(monkeypatch)
    proof = reg.prove(2050)
    assert len(proof.siblings) == 13
    assert calls["leaf"] == 0
    assert calls["node"] <= 2 * 13
    levels = _ref_levels([_ref_leaf(n + 1, "denial", f"e{n}") for n in range(4101)])
    assert proof.siblings == _ref_siblings(levels, 2049)
    assert proof.root == reg.root() == levels[-1][0].hex()


@pytest.mark.parametrize("size", [511, 512, 513, 1023, 1024, 1025, 2049])
def test_large_trees_match_a_full_rebuild(size):
    reg, leaves = Registry(), []
    for n in range(1, size + 1):
        reg.append("execution", f"x{n}")
        leaves.append(_ref_leaf(n, "execution", f"x{n}"))
    levels = _ref_levels(leaves)
    assert reg.root() == levels[-1][0].hex()
    for seq in (1, size // 2, size):
        proof = reg.prove(seq)
        assert (proof.leaves, proof.leaf) == (size, leaves[seq - 1].hex())
        assert proof.siblings == _ref_siblings(levels, seq - 1), seq


def _median_ms(run, times=15):
    spent = []
    for _ in range(times):
        start = time.perf_counter()
        run()
        spent.append(time.perf_counter() - start)
    return statistics.median(spent)


def _costs(size):
    reg = Registry(keypair=(KEY, public_key_of(KEY)))
    for n in range(size):
        reg.append("denial", f"e{n}")
    reg.anchor(1800001000)
    ts = iter(range(1800001001, 1800002000))

    def seal():
        reg.append("denial", "x")
        reg.anchor(next(ts))

    return _median_ms(seal), _median_ms(lambda: reg.prove(size // 2))


def test_seal_and_proof_time_grow_by_log_n():
    # A coarse wall-clock guard; the hard bound is the hash count pinned by
    # test_a_proof_costs_log_n_hashes and test_sealing_and_reloading_...
    small, large = _costs(1000), _costs(4000)
    assert large[0] / small[0] < 2.5
    assert large[1] / small[1] < 2.5


def test_a_failed_append_leaves_the_log_and_its_root_unchanged(tmp_path):
    path = tmp_path / "state.db"
    reg = _sealed(StateStore(path), ["a"])
    root, seals = reg.root(), reg.anchors()
    with pytest.raises(TypeError):
        reg.append("denial", b"x")
    assert (reg.size(), reg.root(), reg.anchors()) == (1, root, seals)
    reg.append("denial", "b")
    sealed = reg.anchor(1800001009)
    leaves = [_ref_leaf(1, "execution", "a"), _ref_leaf(2, "denial", "b")]
    assert (sealed.seq_to, sealed.root) == (2, _ref_levels(leaves)[-1][0].hex())
    again = Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))
    assert (again.size(), again.root()) == (2, sealed.root)


def _batches(path):
    reg = Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))
    roots = {}
    for n in range(1, 9):
        reg.append("denial", f"e{n}")
        roots[n] = reg.root()
        if n in (3, 5, 8):
            reg.anchor(1800001000 + n)
    reg._state.close()
    return roots


def _resign(path, row, **changes):
    """Rewrite the seal stored at row with changes, signed by the gate key."""
    raw = sqlite3.connect(path)
    (text,) = raw.execute("SELECT seal FROM seals WHERE seq_to = ?", (row,)).fetchone()
    unsigned = replace(
        registry_module._anchor_of(json.loads(text)), **changes, signature=b""
    )
    key = Ed25519PrivateKey.from_private_bytes(KEY)
    signed = replace(unsigned, signature=key.sign(unsigned.signable_bytes()))
    view = json.dumps(registry_module._seal_view(signed))
    raw.execute("UPDATE seals SET seal = ? WHERE seq_to = ?", (view, row))
    raw.commit()
    raw.close()


def test_an_intermediate_seal_over_another_root_is_refused(tmp_path):
    path = tmp_path / "state.db"
    roots = _batches(path)
    _resign(path, 5, root=roots[3])
    with pytest.raises(ValueError, match="registry entries do not match their seals"):
        Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))


def test_an_intermediate_seal_over_another_range_is_refused(tmp_path):
    path = tmp_path / "state.db"
    _batches(path)
    _resign(path, 3, seq_to=4)
    _resign(path, 5, seq_from=5)
    with pytest.raises(ValueError, match="registry entries do not match their seals"):
        Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))


@pytest.mark.parametrize("bound", [1.0, True])
def test_a_seal_whose_range_is_not_an_integer_is_refused(tmp_path, bound):
    path = tmp_path / "state.db"
    _sealed(StateStore(path), ["a", "b"])
    _resign(path, 1, seq_from=bound, seq_to=bound)
    with pytest.raises(ValueError, match="registry entries do not match their seals"):
        Registry(keypair=(KEY, public_key_of(KEY)), state=StateStore(path))
