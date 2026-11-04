"""The operator's tool for the Increase sandbox's ACH Simulations API.

Sandbox ACH transfers never reach the Federal Reserve, so their submission,
settlement and return happen only when the operator asks for them here.
Nothing in the payment path imports this module: the agent, the gate and the
desk never simulate anything.
"""

import argparse
import os
import re
import sys
from collections.abc import Mapping
from typing import NoReturn

from increase import APIStatusError, Increase

from bank.api import RailError
from bank.credentials import BANK_KEY_ENV, take_bank_key
from bank.increase import _ach_state, sandbox_client
from bank.reconcile import AchState

STEPS = ("submit", "settle", "return")
REASONS = ("insufficient_fund", "account_closed", "no_account", "payment_stopped")
ACH_ID = re.compile(r"(?:sandbox_)?ach_transfer_[A-Za-z0-9]{1,64}")


def simulate(
    client: Increase,
    step: str,
    transfer_id: str,
    reason: str = "insufficient_fund",
) -> AchState:
    """Ask the sandbox to move an ACH transfer one step along its lifecycle.

    The idempotency key is fixed per step and transfer, so sending the same
    command again replays the bank's first answer instead of acting twice.

    Args:
        client: Increase client pinned to the sandbox.
        step: ``submit``, ``settle`` or ``return``.
        transfer_id: The bank's id for the ACH transfer.
        reason: The return reason, used by ``return`` only.

    Returns:
        The transfer's lifecycle as the bank answered it.

    Raises:
        ValueError: If the step is unknown.
        RailError: If the answer is not this transfer's lifecycle.
    """
    key = f"mandate-simulate-{step}-{transfer_id}"
    simulations = client.simulations.ach_transfers
    if step == "submit":
        answer: object = simulations.submit(transfer_id, idempotency_key=key)
    elif step == "settle":
        answer = simulations.settle(transfer_id, idempotency_key=key)
    elif step == "return":
        answer = simulations.return_(
            transfer_id,
            reason=reason,  # type: ignore[arg-type]
            idempotency_key=key,
        )
    else:
        raise ValueError(f"unknown simulation step: {step}")
    state = _ach_state(answer)
    if state.transfer_id != transfer_id:
        raise RailError("bank: unavailable")
    return state


def _said(state: AchState) -> str:
    """The line that reports the bank's answer."""
    if state.return_code is not None:
        return (
            f"SIMULATED RETURN of ACH transfer {state.transfer_id}: "
            f"{state.return_code} {state.return_reason}"
        )
    if state.settled_at is not None:
        return f"ACH transfer {state.transfer_id}: settled at {state.settled_at}"
    return f"ACH transfer {state.transfer_id}: {state.status}"


def _refused_type(exc: APIStatusError) -> str | None:
    """The bank's error type when a 4xx answer parsed into one; else None."""
    if not 400 <= exc.status_code < 500 or not isinstance(exc.body, Mapping):
        return None
    kind = exc.body.get("type")
    return kind if isinstance(kind, str) else None


def simulate_cli(argv: list[str] | None = None) -> None:
    """Entry point for `mandate-bank-simulate`.

    Args:
        argv: Command-line arguments; ``sys.argv[1:]`` when None.
    """
    parser = argparse.ArgumentParser(
        prog="mandate-bank-simulate",
        description=(
            "Submit, settle or return an ACH transfer in the Increase sandbox; "
            "every return it causes is a SIMULATED RETURN."
        ),
    )
    parser.add_argument("step", choices=STEPS)
    parser.add_argument("transfer_id")
    parser.add_argument("--reason", choices=REASONS, default=REASONS[0])
    args = parser.parse_args(argv)
    if ACH_ID.fullmatch(args.transfer_id) is None:
        parser.exit(2, f"not an ACH transfer id: {args.transfer_id}\n")
    key = take_bank_key(os.environ)
    if key is None:
        parser.exit(2, f"bank rail unavailable: set {BANK_KEY_ENV}\n")
    try:
        state = simulate(sandbox_client(key), args.step, args.transfer_id, args.reason)
    except APIStatusError as exc:
        kind = _refused_type(exc)
        if kind is None:
            _no_answer()
        sys.stderr.write(f"bank refused the simulation: {kind}\n")
        raise SystemExit(1) from None
    except Exception:
        _no_answer()
    print(_said(state))


def _no_answer() -> NoReturn:
    sys.stderr.write("bank unavailable: no answer to the simulation\n")
    raise SystemExit(1)
