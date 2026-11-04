"""The holder's side of a zkTLS balance proof: prove in this process, upload."""

import argparse
import base64
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping
from typing import Any, NoReturn
from urllib.parse import urlsplit

import httpx2

from bank.credentials import HOLDER_KEY_ENV
from evidence.zktls import BANK_HOST, REVEALED_FIELDS, ZKTLS_BIN_ENV, find_verifier

PROVE_TIMEOUT_S = 120.0
# The desk runs its verifier before it answers the upload.
_DESK_TIMEOUT_S = 60.0


_PATH = re.compile(r"/accounts/(sandbox_)?account_[A-Za-z0-9]{1,64}/balance")
_NONCE = re.compile(r"[0-9a-f]{64}")
_NOTARY = re.compile(r"(127\.0\.0\.1|\[::1\]):([0-9]{1,5})")
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def challenge_is_pinned(challenge: Mapping[str, Any]) -> bool:
    """Whether a desk challenge names only the pinned bank lookup.

    The prover sends the holder key to ``host``, so a desk must not choose it;
    nor the path, the revealed fields, a non-hex nonce or a remote notary.
    """
    notary = _NOTARY.fullmatch(_str(challenge.get("notary")))
    return (
        challenge.get("host") == BANK_HOST
        and _PATH.fullmatch(_str(challenge.get("path"))) is not None
        and challenge.get("reveal") == list(REVEALED_FIELDS)
        and _NONCE.fullmatch(_str(challenge.get("nonce"))) is not None
        and notary is not None
        and 0 < int(notary.group(2)) < 65536
    )


def desk_url_is_safe(url: str) -> bool:
    """Whether the desk URL is https, or plain http only to this machine."""
    parts = urlsplit(url)
    if parts.scheme == "https":
        return bool(parts.hostname)
    return parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS


def _error_of(stdout: str) -> str:
    lines = stdout.strip().splitlines()
    try:
        error = json.loads(lines[-1])["error"] if lines else None
    except (ValueError, KeyError, TypeError):
        error = None
    return error if isinstance(error, str) and error else "prover failed"


def prove_presentation(
    binary: str, challenge: Mapping[str, Any], env: Mapping[str, str]
) -> bytes:
    """Run the prover for one challenge and return the presentation bytes.

    The holder key reaches the prover by name only (``--auth-env``), so it is
    never on a command line.

    Args:
        binary: The built ``mandate-zktls``.
        challenge: The desk's open challenge: notary, host, path, nonce and
            revealed fields.
        env: Environment the prover runs with; it holds the holder key.

    Returns:
        The presentation the prover wrote.

    Raises:
        RuntimeError: The challenge is not pinned (the prover never runs), or
            the prover failed; the message is the reason.
        subprocess.TimeoutExpired: The prover ran past ``PROVE_TIMEOUT_S``.
    """
    if not challenge_is_pinned(challenge):
        raise RuntimeError("desk challenge not pinned")
    with tempfile.TemporaryDirectory() as directory:
        out = os.path.join(directory, "presentation.bin")
        done = subprocess.run(  # noqa: S603
            [
                binary,
                "prove",
                "--notary",
                str(challenge["notary"]),
                "--host",
                str(challenge["host"]),
                "--path",
                str(challenge["path"]),
                "--nonce",
                str(challenge["nonce"]),
                "--reveal",
                ",".join(challenge["reveal"]),
                "--auth-env",
                HOLDER_KEY_ENV,
                "--out",
                out,
            ],
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=PROVE_TIMEOUT_S,
            check=False,
        )
        if done.returncode != 0:
            raise RuntimeError(_error_of(done.stdout))
        with open(out, "rb") as handle:
            return handle.read()


def _refused(reason: str) -> NoReturn:
    print(f"Funds proof refused: {reason}", flush=True)
    raise SystemExit(1)


def _post(client: httpx2.Client, url: str, body: dict[str, str]) -> dict[str, Any]:
    try:
        answer = client.post(url, json=body)
    except httpx2.HTTPError:
        _refused("desk unreachable")
    try:
        view = answer.json()
    except ValueError:
        view = None
    if not isinstance(view, dict):
        _refused(f"desk answered {answer.status_code}")
    return view


def _reason(view: Mapping[str, Any]) -> str:
    for key in ("reason", "error", "status"):
        if isinstance(view.get(key), str):
            return str(view[key])
    return "desk answered no status"


def cli(
    argv: list[str] | None = None, http_client: httpx2.Client | None = None
) -> None:
    """Console entry point for `mandate-holder-proof`.

    Asks the desk for an intent's funds challenge, proves the Increase sandbox
    balance through Mandate's notary with the holder's own key, and uploads
    the presentation. This is the only process that holds
    ``INCREASE_HOLDER_API_KEY``; its value is never printed.

    Args:
        argv: Command-line arguments; None reads ``sys.argv``.
        http_client: Client for the desk; None opens one.
    """
    parser = argparse.ArgumentParser(
        prog="mandate-holder-proof",
        description="Prove your Increase sandbox balance for a signed intent.",
    )
    parser.add_argument("--desk", required=True, help="desk URL, e.g. http://...")
    parser.add_argument("--intent", required=True, help="the signed intent's id")
    args = parser.parse_args(argv)
    if not os.environ.get(HOLDER_KEY_ENV):
        parser.exit(2, f"holder proof unavailable: set {HOLDER_KEY_ENV}\n")
    binary = find_verifier(os.environ)
    if binary is None:
        parser.exit(
            2,
            f"holder proof unavailable: set {ZKTLS_BIN_ENV} to a built mandate-zktls\n",
        )
    if not desk_url_is_safe(args.desk):
        _refused("desk URL must be https or loopback")
    desk = args.desk.rstrip("/")
    with http_client or httpx2.Client(timeout=_DESK_TIMEOUT_S) as client:
        challenge = _post(
            client, f"{desk}/api/intent/funds-challenge", {"intent_id": args.intent}
        )
        if challenge.get("status") != "open":
            _refused(_reason(challenge))
        try:
            presentation = prove_presentation(binary, challenge, os.environ)
        except RuntimeError as exc:
            _refused(str(exc))
        except subprocess.TimeoutExpired:
            _refused("prover timed out")
        result = _post(
            client,
            f"{desk}/api/intent/funds-proof",
            {
                "intent_id": args.intent,
                "presentation": base64.b64encode(presentation).decode("ascii"),
            },
        )
    if result.get("status") != "proven":
        _refused(_reason(result))
    print(f"Funds proven for {args.intent}: {result['evidence_ref']}", flush=True)
