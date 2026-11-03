"""Reasoning anchor: binds a certificate to the exact Meta response.

The anchor records the model, response id and encrypted reasoning blobs of
one Meta call. It proves binding and non-substitution after issuance. It does
not prove that Meta authenticates or re-verifies the reasoning.
"""

import hashlib
import json
from dataclasses import dataclass

from gate.certs import read_claims
from swarm.meta_client import Item, MetaTrace, check_blob, reasoning_commitment

_ANCHOR_DOMAIN = b"mandate/anchor/v1\n"
_VERSION = 1


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


@dataclass(frozen=True)
class ReasoningAnchor:
    """Identity of one Meta response and its encrypted reasoning.

    Args:
        v: Anchor format version; only 1 is supported.
        model: Model id echoed by the API.
        response_id: Response id (resp_...).
        blobs: encrypted_content of each reasoning item, in order.
    """

    v: int
    model: str
    response_id: str
    blobs: tuple[str, ...]

    def __post_init__(self) -> None:
        if isinstance(self.v, bool) or self.v != _VERSION:
            raise ValueError("unsupported anchor version")
        for blob in self.blobs:
            check_blob(blob)

    def digest(self) -> str:
        """Domain-separated SHA-256 over model, response id and reasoning."""
        reasoning = reasoning_commitment(
            [{"type": "reasoning", "encrypted_content": b} for b in self.blobs]
        )
        body = _canonical(
            {
                "model": self.model,
                "reasoning": reasoning,
                "response_id": self.response_id,
            }
        )
        return hashlib.sha256(_ANCHOR_DOMAIN + body).hexdigest()

    def to_json(self) -> str:
        """Compact JSON with sorted keys."""
        return _canonical(
            {
                "blobs": list(self.blobs),
                "model": self.model,
                "response_id": self.response_id,
                "v": self.v,
            }
        ).decode("ascii")

    @classmethod
    def from_json(cls, text: str) -> "ReasoningAnchor":
        """Parse an anchor written by to_json.

        Raises:
            ValueError: On an unsupported version or any malformed shape.
        """
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ValueError("malformed anchor") from exc
        if (
            isinstance(data, dict)
            and isinstance(data.get("v"), int)
            and not isinstance(data["v"], bool)
            and data["v"] != _VERSION
        ):
            raise ValueError("unsupported anchor version")
        if not isinstance(data, dict) or set(data) != {
            "blobs",
            "model",
            "response_id",
            "v",
        }:
            raise ValueError("malformed anchor")
        v, model, rid, blobs = (
            data["v"],
            data["model"],
            data["response_id"],
            data["blobs"],
        )
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("malformed anchor")
        if (
            not isinstance(model, str)
            or not isinstance(rid, str)
            or not isinstance(blobs, list)
            or not all(isinstance(b, str) for b in blobs)
        ):
            raise ValueError("malformed anchor")
        try:
            return cls(v=v, model=model, response_id=rid, blobs=tuple(blobs))
        except ValueError as exc:
            raise ValueError("malformed anchor") from exc


def anchor_from(trace: MetaTrace, output: tuple[Item, ...]) -> ReasoningAnchor:
    """Anchor a Meta response from its trace and output items.

    Raises:
        ValueError: When a reasoning item lacks encrypted_content.
    """
    reasoning_commitment(output)  # validates every reasoning item
    blobs = tuple(
        str(i["encrypted_content"]) for i in output if i.get("type") == "reasoning"
    )
    return ReasoningAnchor(
        v=_VERSION, model=trace.model, response_id=trace.response_id, blobs=blobs
    )


def verify_anchor(
    anchor: ReasoningAnchor, token: str, public_key: bytes
) -> tuple[bool, str]:
    """Check that a certificate commits to this exact anchor.

    Reads the signed claims without freshness or consumption, so auditors can
    verify long after issuance.

    Args:
        anchor: Anchor presented alongside the certificate.
        token: Compact JWS certificate.
        public_key: Raw Ed25519 public key of the issuer.

    Returns:
        ``(True, "ok: anchor bound")`` or ``(False, reason)``.
    """
    subject, reason = read_claims(token, public_key)
    if subject is None:
        return (False, reason)
    commitment = subject.get("reasoning_commitment")
    if commitment is None:
        return (False, "malformed: no reasoning commitment")
    if commitment != anchor.digest():
        return (False, "mismatch: reasoning differs")
    return (True, "ok: anchor bound")
