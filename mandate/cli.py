"""Command-line interface for governed bank transfers."""

import argparse
import secrets
import sys
import time
from pathlib import Path

from bank.verifier import Verifier
from gate.certs import generate_keypair
from gate.policy import Intent
from gate.shim import Mode, RawCall
from mandate.client import RunRequest, build_bank, load_policy, run_governed


def build_parser() -> argparse.ArgumentParser:
    """Build the mandate command-line parser.

    Returns:
        Parser with the required `run` subcommand.
    """
    parser = argparse.ArgumentParser(prog="mandate")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--policy", required=True)
    run.add_argument("--amount-cents", required=True, type=int)
    run.add_argument("--currency", required=True)
    run.add_argument("--to", required=True)
    run.add_argument("--from", required=True, dest="from_acct")
    run.add_argument("--ref", required=True)
    run.add_argument("--mode", choices=("enforce", "shadow"), default="enforce")
    run.add_argument("--now", type=int, default=None)
    run.add_argument("--nonce", default=None)
    run.add_argument("--scope", default="mandate-cli")
    run.add_argument("--reasoning-commitment", default="00" * 32)
    run.add_argument("--revocation-index", type=int, default=0)
    run.add_argument("--fund-cents", type=int, default=100000)
    run.add_argument("--evidence-ref", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one governed transfer from command-line arguments.

    Args:
        argv: Argument vector without the program name; uses sys.argv when None.

    Returns:
        Exit status: 0 executed, 3 denied, 2 usage or policy error.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.amount_cents <= 0:
        parser.error("amount must be positive")
    if args.revocation_index < 0:
        parser.error("revocation index must be >= 0")
    now = args.now if args.now is not None else int(time.time())
    nonce = args.nonce if args.nonce is not None else secrets.token_hex(16)
    try:
        policy = load_policy(Path(args.policy))
    except FileNotFoundError:
        print(f"policy file not found: {args.policy}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    call = RawCall(
        runtime="cli",
        executable="bank.pay",
        operation="transfer",
        args=(
            ("amount", str(args.amount_cents)),
            ("currency", args.currency),
            ("from", args.from_acct),
            ("to", args.to),
            ("ref", args.ref),
        ),
        category="payments",
        evidence_refs=tuple(args.evidence_ref),
        reversible=False,
    )
    intent = Intent(
        amount_cents=args.amount_cents,
        currency=args.currency,
        recipient=args.to,
        reference=args.ref,
    )
    private_key, public_key = generate_keypair()
    bank = build_bank(args.from_acct, args.to, args.fund_cents)
    result = run_governed(
        RunRequest(
            call=call,
            policy=policy,
            intent=intent,
            private_key=private_key,
            mode=Mode(args.mode.upper()),
            now=now,
            nonce=nonce,
            timestamp=now,
            scope=args.scope,
            reasoning_commitment=args.reasoning_commitment,
            revocation_index=args.revocation_index,
        ),
        bank,
        Verifier(public_key),
    )
    event = result.event.event_id
    if result.payment is not None:
        print(f"EXECUTED payment={result.payment.payment_id} event={event}")
        return 0
    print(f"DENIED reason={result.reason} event={event}")
    return 3
