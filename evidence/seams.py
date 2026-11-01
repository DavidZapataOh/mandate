"""Labeled evidence references with cooperative fallback."""

import hashlib

from evidence.cooperative import SignedState

COOPERATIVE_KIND = "cooperative-signed"
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
    if kind not in (COOPERATIVE_KIND, ZKTLS_KIND):
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
