"""What a report must cite beyond console lines: registry, policies, bank, holders."""

from dataclasses import asdict
from typing import Any

from bank.rail import BankRail
from bank.verifier import Verifier
from gate.policy import Policy
from swarm.desk import DESK_POLICY, PaymentDesk
from swarm.flow import PAYMENTS_POLICY
from swarm.hub import EventHub
from swarm.nimbus import NIMBUS_POLICY

SERVED_POLICIES: tuple[Policy, ...] = (DESK_POLICY, PAYMENTS_POLICY, NIMBUS_POLICY)


def _policy(policy: Policy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "rules": [asdict(rule) for rule in policy.rules],
    }


def provenance(hub: EventHub, desk: PaymentDesk) -> dict[str, Any]:
    """Facts no console line carries: epoch, window, registry, policies, bank, holders.

    Args:
        hub: The hub whose retained lines the report covers.
        desk: The desk whose registry, policies, latest reconciliation
            with the bank and paired holder count the report cites.

    Returns:
        A JSON-ready mapping.
    """

    def registry(_bank: BankRail, _verifier: Verifier) -> dict[str, Any]:
        return {"root": desk.registry.root(), "leaves": desk.registry.size()}

    retained = hub.since(0)
    return {
        "epoch": hub.epoch,
        "window": {
            "first_seq": retained[0].seq if retained else 0,
            "last_seq": retained[-1].seq if retained else 0,
            "retained": len(retained),
        },
        "registry": desk.guarded(registry),
        "policies": [_policy(policy) for policy in SERVED_POLICIES],
        "bank": desk.latest_reconciliation(),
        # Outside `guarded`: holder_keys takes the desk lock, which is not
        # re-entrant.
        "holders": len(desk.holder_keys),
    }
