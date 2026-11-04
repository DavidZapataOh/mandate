"""Proof receipts: a confirmed payment's evidence as one SD-JWT bundle.

The holder copy carries every Disclosure; ``present`` drops the ones the
holder keeps back without re-signing, so an auditor copy still verifies
against the gate key while its personal fields stay salted digests.
"""

import base64
import json
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from bank.api import Payment
from bank.rail import bank_view
from gate.cava import CavaAction, canonical_bytes
from gate.consent import Consent
from gate.policy import Policy, matched_rule
from gate.registry import Anchor, InclusionProof, LogEntry
from gate.sdjwt import conceal, issue, serialize
from swarm.anchor import ReasoningAnchor

RECEIPT_TYP = "mandate-receipt+sd-jwt"
GROUPS: dict[str, tuple[tuple[str, str], ...]] = {
    "amount": (("consent", "amount_cents"), ("consent", "currency")),
    "payee": (("consent", "recipient"),),
    "account": (("consent", "source"),),
    "reference": (("consent", "reference"),),
    "holder": (("consent", "holder_key"), ("consent", "key_signature")),
}
# Each of these opens every hidden field (the targets name them, the salt and
# the signature confirm a guess), so they go out only with all four groups.
FULL = (("cava", "targets"), ("cava", "action_salt"), ("consent", "signature"))
_ACTION_SALT = 32
_FIELD_GROUPS = frozenset({"amount", "payee", "account", "reference"})
_CAVA_CONCEALED = ("targets", "action_salt")
_CONSENT_CONCEALED = (
    "amount_cents",
    "currency",
    "recipient",
    "reference",
    "source",
    "signature",
    "holder_key",
    "key_signature",
)
_CONSENT_ENCODED = ("signature", "consent_key", "key_signature")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64u_json(text: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))


def seal_view(seal: Anchor) -> dict[str, Any]:
    """JSON view of a registry seal with its signature in standard base64."""
    return {**asdict(seal), "signature": _b64(seal.signature)}


def _consent_claims(consent: Consent, holder_key: bytes) -> dict[str, Any]:
    claims = asdict(consent)
    for name in _CONSENT_ENCODED:
        claims[name] = _b64(claims[name])
    claims["holder_key"] = _b64(holder_key)
    return claims


def _cert_jti(certificate: str) -> Any:
    return _b64u_json(certificate.split(".")[1])["jti"]


def proof_receipt(
    payment_id: str,
    certificate: str,
    action: CavaAction,
    policy: Policy,
    consent: Consent,
    holder_key: bytes,
    entry: LogEntry,
    proof: InclusionProof,
    seal: Anchor,
    gate_key: bytes,
    salt: Callable[[], bytes],
    reasoning: ReasoningAnchor | None = None,
    *,
    action_salt: bytes,
    payment: Payment | None = None,
) -> dict[str, Any]:
    """Holder copy of a payment's receipt, with every Disclosure.

    Args:
        payment_id: Executed payment.
        certificate: Compact JWS certificate the gate issued for it.
        action: Canonical action the certificate's hash covers.
        policy: Policy the gate decided under.
        consent: The holder's signed consent.
        holder_key: Paired holder key that certified the one-time consent key.
        entry: Registry entry of the execution.
        proof: Inclusion proof of ``entry``.
        seal: Signed registry seal covering ``proof.root``.
        gate_key: Raw Ed25519 private key the gate signs with.
        salt: Source of 16-byte Disclosure salts, one per concealed claim.
        reasoning: Reasoning anchor bound to the certificate, if any.
        action_salt: 32-byte key of the certificate's action hash.
        payment: The payment the bank rail executed; its rail, transfer id
            and idempotency key are signed, always visible, as ``bank``.

    Returns:
        The receipt dict in wire order.

    Raises:
        ValueError: If no rule of ``policy`` matches ``action``, if
            ``action_salt`` is not 32 bytes, or if ``salt`` draws fewer than
            16 bytes.
    """
    if len(action_salt) != _ACTION_SALT:
        raise ValueError("receipt: action salt must be 32 bytes")
    rule = matched_rule(action, policy)
    if rule is None:
        raise ValueError("receipt: no matching rule")
    canonical = json.loads(canonical_bytes(action))
    cava, cava_found = conceal(
        {**canonical, "action_salt": action_salt.hex()}, _CAVA_CONCEALED, salt
    )
    signed, consent_found = conceal(
        _consent_claims(consent, holder_key), _CONSENT_CONCEALED, salt
    )
    token = issue(
        {
            "iss": "mandate",
            "iat": seal.ts,
            "sub": payment_id,
            "cert_jti": _cert_jti(certificate),
            "cava": cava,
            "consent": signed,
            "bank": bank_view(payment),
        },
        gate_key,
        RECEIPT_TYP,
    )
    disclosures = [cava_found[n] for n in _CAVA_CONCEALED]
    disclosures += [consent_found[n] for n in _CONSENT_CONCEALED]
    return {
        "v": 2,
        "payment_id": payment_id,
        "certificate": certificate,
        "sd": serialize(token, disclosures),
        "policy": {
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "rule_id": rule.rule_id,
        },
        "registry": {
            "entry": asdict(entry),
            "proof": {**asdict(proof), "siblings": list(proof.siblings)},
            "seal": seal_view(seal),
        },
        "reasoning": None if reasoning is None else json.loads(reasoning.to_json()),
    }


def present(receipt: dict[str, Any], reveal: frozenset[str]) -> dict[str, Any]:
    """The receipt keeping only the Disclosures of the revealed groups.

    Args:
        receipt: A holder copy (or any presentation of one).
        reveal: Group names from ``GROUPS``; the four field groups together
            also reveal ``FULL``.

    Returns:
        The same receipt with a narrowed ``sd``; the gate-signed JWT is
        unchanged.

    Raises:
        ValueError: On a group name not in ``GROUPS``.
    """
    for group in sorted(reveal):
        if group not in GROUPS:
            raise ValueError(f"receipt: unknown group {group}")
    names = {name for group in reveal for _, name in GROUPS[group]}
    if _FIELD_GROUPS <= reveal:
        names |= {name for _, name in FULL}
    token, *texts, _ = receipt["sd"].split("~")
    kept = [text for text in texts if _b64u_json(text)[1] in names]
    return {**receipt, "sd": serialize(token, kept)}
