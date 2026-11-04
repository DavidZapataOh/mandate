"""The open-weights attacker behind the console, one model call at a time."""

import threading
from collections.abc import Mapping
from typing import TYPE_CHECKING

import httpx2

from swarm.attacker import Attacker, attacker_from_env
from swarm.console_line import ConsoleLine
from swarm.redteam import AttackKind

if TYPE_CHECKING:
    from swarm.console import AttackRunner

ATTACKER_OFF = "Live attacker off: start mandate-console with --live-attacker"
NO_ATTACKER_KEY = "No attacker key: set BASETEN_API_KEY or a Meta key"
_DETAIL_MAX = 240


class AttackerUnavailableError(Exception):
    """No attacker is configured; the message says why."""


class AttackerBusyError(Exception):
    """A model attack is already in flight."""


class NoPlanError(Exception):
    """The model gave no usable plan; the message is the reply detail."""


class LiveAttacker:
    """Asks the attacker for a plan and applies it through the runner.

    Args:
        runner: Runner that applies the plan and publishes its line.
        attacker: The model client, or None when no attacker is available.
        reason: Why there is no attacker.
    """

    def __init__(
        self,
        runner: "AttackRunner",
        attacker: Attacker | None,
        reason: str | None = None,
    ) -> None:
        self._runner = runner
        self._attacker = attacker
        self._reason = reason
        self._lock = threading.Lock()

    @property
    def busy(self) -> bool:
        """Whether a model attack is in flight."""
        return self._lock.locked()

    def status(self) -> dict[str, object]:
        """The attacker state the attack menu reports."""
        if self._attacker is None:
            return {
                "available": False,
                "provider": None,
                "model": None,
                "reason": self._reason,
            }
        return {
            "available": True,
            "provider": self._attacker.provider,
            "model": self._attacker.model,
            "reason": None,
        }

    def ask(self, kind: AttackKind) -> ConsoleLine:
        """Ask the model for one attack of this kind and run it at the gate.

        Args:
            kind: Attack kind to request.

        Returns:
            The published console line.

        Raises:
            AttackerUnavailableError: No attacker is configured.
            AttackerBusyError: Another model attack is in flight.
            NoPlanError: The model gave no usable plan; nothing is published.
        """
        if self._attacker is None:
            raise AttackerUnavailableError(self._reason or ATTACKER_OFF)
        if not self._lock.acquire(blocking=False):
            raise AttackerBusyError("attacker busy")
        try:
            plan, trace, text = self._attacker.next_plan(
                kind, self._runner.legit_call()
            )
        finally:
            self._lock.release()
        if plan is None:
            raise NoPlanError(text[:_DETAIL_MAX])
        return self._runner.apply(plan, trace)


def live_attacker(
    runner: "AttackRunner",
    env: Mapping[str, str],
    enabled: bool,
    http_client: httpx2.Client | None = None,
) -> LiveAttacker:
    """Build the live attacker; only `enabled` runs ever spend model calls.

    Args:
        runner: Runner that applies the plans.
        env: Environment holding the provider keys.
        enabled: Whether the operator opted in.
        http_client: Optional HTTP client; injectable for tests.
    """
    if not enabled:
        return LiveAttacker(runner, None, ATTACKER_OFF)
    try:
        return LiveAttacker(runner, attacker_from_env(env, http_client))
    except KeyError:
        return LiveAttacker(runner, None, NO_ATTACKER_KEY)
