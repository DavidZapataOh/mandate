"""Adversarial call builders for attack drills."""

from gate.broker import Delegation, Scope, mint
from gate.cava import CavaAction, Freshness
from gate.certs import generate_keypair
from gate.mcp_proxy import ProxyCall


def poisoned_call(tool: str, scope: str) -> ProxyCall:
    """Deadbugz-style exfil attempt against bank-mcp."""
    return ProxyCall(server="bank-mcp", tool=tool, scope=scope)


def narrow_chain() -> tuple[tuple[Delegation, ...], bytes, Scope]:
    """One-link chain narrowing root scope to bank.pay at cap 5000."""
    root_priv, root_pub = generate_keypair()
    _, child_pub = generate_keypair()
    root_scope = Scope(atoms=("mcp:bank.pay", "domain:acme.com"), max_spend_cents=20000)
    leaf = mint(
        root_priv,
        root_pub,
        child_pub,
        Scope(atoms=("mcp:bank.pay",), max_spend_cents=5000),
        root_scope,
        1800003600,
        7,
    )
    return ((leaf,), root_pub, root_scope)


def _drill_action(targets: tuple[str, ...]) -> CavaAction:
    return CavaAction(
        version="cava/1",
        runtime="mcp",
        executable="bank.pay",
        operation="transfer",
        category="payments",
        targets=targets,
        reversible=False,
        freshness=Freshness(nonce="e" * 32, timestamp=1800000000),
        evidence_refs=(),
    )


def narrow_action() -> CavaAction:
    """In-scope payment inside the narrowed delegation."""
    return _drill_action(("mcp:bank.pay", "amount:USD:100"))


def over_target_action() -> CavaAction:
    """Escalation attempt reaching past the delegated atoms."""
    return _drill_action(("mcp:bank.pay", "domain:evil.com", "amount:USD:100"))


def over_spend_action() -> CavaAction:
    """Escalation attempt spending past the delegated cap."""
    return _drill_action(("mcp:bank.pay", "amount:USD:6000"))
