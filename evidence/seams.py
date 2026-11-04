"""Labeled evidence references with cooperative fallback."""

import hashlib

from evidence.cooperative import SignedState
from gate.policy import Intent
from swarm.intent import intent_bytes

COOPERATIVE_KIND = "cooperative-signed"
INTENT_KIND = "holder-intent"
ZKTLS_KIND = "zktls-attestation"
FIXTURE_ENDPOINT = "tlsn-server-fixture"
FIXTURE_CONTENT = "example-json"


def evidence_ref(kind: str, digest: str) -> str:
    """Build a labeled evidence reference.

    Args:
        kind: Evidence kind, one of the module kind constants.
        digest: Hex digest identifying the evidence bytes.

    Returns:
        Reference of the form `"ev:{kind}:{digest}"`.

    Raises:
        ValueError: If the kind is unknown.
    """
    if kind not in (COOPERATIVE_KIND, INTENT_KIND, ZKTLS_KIND):
        raise ValueError(f"unknown evidence kind: {kind}")
    return f"ev:{kind}:{digest}"


def select_cooperative(state: SignedState) -> str:
    """Reference the cooperative signed state.

    Args:
        state: The bank-signed state to reference.

    Returns:
        Cooperative evidence ref over the state's signable bytes.
    """
    digest = hashlib.sha256(state.signable_bytes()).hexdigest()[:32]
    return evidence_ref(COOPERATIVE_KIND, digest)


def opaque_cooperative_ref(state: SignedState) -> str:
    """Reference a cooperative signed state without committing to its balance.

    Every unsigned field but the balance is known or guessable, so a hash of
    the signable bytes alone could be brute-forced over the balance. Hashing
    the bank's signature in keeps the balance from such a search.

    Args:
        state: The bank-signed state to reference.

    Returns:
        Cooperative evidence ref over the signable bytes and the signature.
    """
    digest = hashlib.sha256(state.signable_bytes() + state.signature).hexdigest()
    return evidence_ref(COOPERATIVE_KIND, digest[:32])


def opaque_intent_ref(intent: Intent, signature: bytes) -> str:
    """Reference a holder-signed intent without committing to its fields.

    The intent bytes are only amount, currency, payee and reference, so a hash
    of them alone would confirm a guess of those fields. The holder signature
    cannot be guessed, which keeps a guessed amount, payee and reference from
    being confirmed against the ref.

    Args:
        intent: The intent the holder signed.
        signature: The holder's 64-byte Ed25519 signature over its bytes.

    Returns:
        Holder-intent evidence ref over the intent bytes and the signature.

    Raises:
        IntentError: If the intent is malformed.
    """
    digest = hashlib.sha256(intent_bytes(intent) + signature).hexdigest()
    return evidence_ref(INTENT_KIND, digest[:32])


def select_zktls(presentation: bytes) -> str:
    """Reference a zkTLS presentation.

    Args:
        presentation: Raw presentation bytes to reference.

    Returns:
        zkTLS evidence ref over the presentation bytes.
    """
    digest = hashlib.sha256(presentation).hexdigest()[:32]
    return evidence_ref(ZKTLS_KIND, digest)


def select_best(state: SignedState | None, presentation: bytes | None) -> str:
    """Select the best available evidence reference.

    Args:
        state: Cooperative signed state, or None when unavailable.
        presentation: zkTLS presentation bytes, or None when unavailable.

    Returns:
        The zkTLS ref when a presentation exists, else the cooperative ref.

    Raises:
        ValueError: If neither evidence source is available.
    """
    if presentation is not None:
        return select_zktls(presentation)
    if state is not None:
        return select_cooperative(state)
    raise ValueError("no evidence available")
