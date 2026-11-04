"""Verify zkTLS presentations of an Increase balance lookup."""

import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidence.seams import select_zktls

ZKTLS_BIN_ENV = "MANDATE_ZKTLS_BIN"
BANK_HOST = "sandbox.increase.com"
REVEALED_FIELDS = ("account_id", "available_balance")
MAX_PRESENTATION_BYTES = 65_536
PROOF_TTL_S = 300
CLOCK_SKEW_S = 30
VERIFY_TIMEOUT_S = 30.0

_REQUEST = re.compile(r"GET /accounts/([A-Za-z0-9_]+)/balance HTTP/1\.1\r\n")
_HEADER_END = re.compile(r"\r\n\x00*\r\n")
_ACCOUNT = re.compile(r'"account_id"\s*:\s*"([A-Za-z0-9_]+)"')
_BALANCE = re.compile(r'"available_balance"\s*:\s*(-?[0-9]{1,18})(?=[\s,}\x00])')


class ZktlsError(Exception):
    """A zkTLS presentation or its verifier was refused."""


def _refuse(reason: str) -> ZktlsError:
    return ZktlsError(f"zktls: {reason}")


@dataclass(frozen=True)
class Disclosed:
    """What the verifier authenticated; hidden bytes are NUL."""

    server_name: str
    time: int
    notary_key: str
    sent: str
    recv: str


@dataclass(frozen=True)
class BalanceProof:
    """A checked balance lookup of the payer's account."""

    evidence_ref: str
    presentation_sha256: str
    account_id: str
    available_balance: int
    session_time: int
    notary_key: str


def find_verifier(env: Mapping[str, str]) -> str | None:
    """Return the verifier binary named by the environment if it is executable."""
    path = env.get(ZKTLS_BIN_ENV)
    if path and os.path.isfile(path) and os.access(path, os.X_OK):
        return path
    return None


def read_output(stdout: str) -> Disclosed:
    """Parse the last line of the verifier's output.

    Raises:
        ZktlsError: The presentation was refused or the output is malformed.
    """
    lines = [line for line in stdout.splitlines() if line.strip()]
    try:
        data = json.loads(lines[-1])
    except (IndexError, ValueError):
        raise _refuse("verifier output malformed") from None
    if not isinstance(data, dict):
        raise _refuse("verifier output malformed")
    if data.get("ok") is False:
        raise _refuse("presentation invalid")
    server_name, time, notary_key, sent, recv = (
        data.get(k) for k in ("server_name", "time", "notary_key", "sent", "recv")
    )
    if (
        data.get("ok") is not True
        or isinstance(time, bool)
        or not isinstance(time, int)
        or not isinstance(server_name, str)
        or not isinstance(notary_key, str)
        or not isinstance(sent, str)
        or not isinstance(recv, str)
    ):
        raise _refuse("verifier output malformed")
    return Disclosed(server_name, time, notary_key, sent, recv)


def run_verifier(binary: str, presentation: bytes) -> Disclosed:
    """Run the verifier on a presentation.

    Raises:
        ZktlsError: The size, the run or the output was refused.
    """
    if not 0 < len(presentation) <= MAX_PRESENTATION_BYTES:
        raise _refuse("presentation size refused")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "presentation.bin"
        path.write_bytes(presentation)
        try:
            done = subprocess.run(  # noqa: S603
                [binary, "verify", "--presentation", str(path)],
                capture_output=True,
                text=True,
                timeout=VERIFY_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise _refuse("verifier timed out") from None
        except OSError:
            raise _refuse("verifier unavailable") from None
    return read_output(done.stdout)


def check_balance(
    disclosed: Disclosed,
    presentation: bytes,
    *,
    notary_key: str,
    account_id: str,
    nonce: str,
    now: int,
) -> BalanceProof:
    """Accept only a fresh, intent-bound balance lookup of `account_id`.

    Raises:
        ZktlsError: Any check failed; the message names the reason.
    """
    if disclosed.notary_key != notary_key:
        raise _refuse("wrong notary")
    if disclosed.server_name != BANK_HOST:
        raise _refuse("wrong server")
    if now - disclosed.time > PROOF_TTL_S:
        raise _refuse("stale session")
    if disclosed.time > now + CLOCK_SKEW_S:
        raise _refuse("session in the future")
    sent = disclosed.sent
    request = _REQUEST.match(sent)
    if request is None or f"\r\nhost: {BANK_HOST}\r\n" not in sent:
        raise _refuse("wrong request")
    if request.group(1) != account_id:
        raise _refuse("different account")
    if sent.count(f"\r\nmandate-nonce: {nonce}\r\n") != 1:
        raise _refuse("not bound to this intent")
    recv = disclosed.recv
    if not recv.startswith("HTTP/1.1 200 OK\r\n"):
        raise _refuse("bank did not answer 200")
    # Hidden header bytes are NUL, so the blank line may be split by a run of them.
    body = _HEADER_END.split(recv, maxsplit=1)[-1] if _HEADER_END.search(recv) else ""
    accounts = _ACCOUNT.findall(body)
    if len(accounts) != 1 or body.count('"account_id"') != 1:
        raise _refuse("account not disclosed")
    if accounts[0] != account_id:
        raise _refuse("different account")
    balances = _BALANCE.findall(body)
    if len(balances) != 1 or body.count('"available_balance"') != 1:
        raise _refuse("balance not disclosed")
    digest = hashlib.sha256(presentation).hexdigest()
    return BalanceProof(
        evidence_ref=select_zktls(presentation),
        presentation_sha256=digest,
        account_id=account_id,
        available_balance=int(balances[0]),
        session_time=disclosed.time,
        notary_key=notary_key,
    )


@dataclass(frozen=True)
class BankProofSetup:
    """The desk's verifier, notary and the payer accounts it can prove."""

    binary: str
    notary_address: str
    notary_key: str
    account_ids: Mapping[str, str]

    def _account(self, account: str) -> str:
        account_id = self.account_ids.get(account)
        if account_id is None:
            raise _refuse("unknown account")
        return account_id

    def challenge(self, account: str, nonce: str) -> dict[str, Any]:
        """Describe the session the holder must prove for `account`."""
        account_id = self._account(account)
        return {
            "host": BANK_HOST,
            "path": f"/accounts/{account_id}/balance",
            "nonce": nonce,
            "notary": self.notary_address,
            "notary_key": self.notary_key,
            "reveal": list(REVEALED_FIELDS),
        }

    def verify(
        self, presentation: bytes, account: str, nonce: str, now: int
    ) -> BalanceProof:
        """Verify a presentation for `account` bound to `nonce`."""
        account_id = self._account(account)
        disclosed = run_verifier(self.binary, presentation)
        return check_balance(
            disclosed,
            presentation,
            notary_key=self.notary_key,
            account_id=account_id,
            nonce=nonce,
            now=now,
        )
