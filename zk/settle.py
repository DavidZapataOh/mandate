"""Async settlement records attaching proof hashes to receipts."""

import hashlib
from dataclasses import dataclass

CIRCUIT_ID = "threshold/v1"


@dataclass(frozen=True)
class Settlement:
    """A recorded settlement binding a receipt to proof hashes.

    Args:
        receipt_ref: Caller-supplied receipt reference.
        circuit: Circuit identifier that produced the proof.
        proof_sha256: Hex digest of the proof bytes.
        vk_sha256: Hex digest of the verifying-key bytes.
        settled_at: Caller-supplied settlement timestamp.
    """

    receipt_ref: str
    circuit: str
    proof_sha256: str
    vk_sha256: str
    settled_at: int


def settle(receipt_ref: str, proof: bytes, vk: bytes, settled_at: int) -> Settlement:
    """Record a settlement for a receipt from proof and verifying-key bytes.

    Args:
        receipt_ref: Receipt reference to attach the settlement to.
        proof: Proof bytes; only the hash is retained.
        vk: Verifying-key bytes; only the hash is retained.
        settled_at: Caller-supplied settlement timestamp.

    Returns:
        The recorded settlement.

    Raises:
        ValueError: If the receipt ref is empty or proof/vk bytes are empty.
    """
    if not proof or not vk:
        raise ValueError("settlement needs proof and vk bytes")
    if not receipt_ref:
        raise ValueError("receipt ref must be non-empty")
    return Settlement(
        receipt_ref=receipt_ref,
        circuit=CIRCUIT_ID,
        proof_sha256=hashlib.sha256(proof).hexdigest(),
        vk_sha256=hashlib.sha256(vk).hexdigest(),
        settled_at=settled_at,
    )
