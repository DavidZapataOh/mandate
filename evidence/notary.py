"""Mandate's own notary: the child process that co-signs bank sessions."""

import json
import os
import select
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

NOTARY_LISTEN = "127.0.0.1:7047"
START_TIMEOUT_S = 10.0


class NotaryError(Exception):
    """The notary child did not start as pinned."""


def new_notary_key() -> bytes:
    """Draw a fresh secp256k1 private key as 32 big-endian bytes."""
    key = ec.generate_private_key(ec.SECP256K1())
    return key.private_numbers().private_value.to_bytes(32, "big")


def notary_public_key(key: bytes) -> str:
    """Return the compressed public point of `key` as hex."""
    private = ec.derive_private_key(int.from_bytes(key, "big"), ec.SECP256K1())
    return (
        private.public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )
        .hex()
    )


@dataclass
class Notary:
    """A running notary child and the key it reported."""

    process: "subprocess.Popen[str]"
    address: str
    public_key: str

    def stop(self) -> None:
        """Kill the child and reap it."""
        self.process.kill()
        self.process.wait()
        if self.process.stdout is not None:
            self.process.stdout.close()


def _kill(process: "subprocess.Popen[str]") -> None:
    process.kill()
    process.wait()
    if process.stdout is not None:
        process.stdout.close()


def _first_line(process: "subprocess.Popen[str]") -> str:
    assert process.stdout is not None  # noqa: S101
    ready, _, _ = select.select([process.stdout], [], [], START_TIMEOUT_S)
    return process.stdout.readline() if ready else ""


def start_notary(binary: str, key: bytes, listen: str = NOTARY_LISTEN) -> Notary:
    """Start the notary child and pin the key it reports.

    The key reaches the child through a 0600 file that is removed as soon as
    the child has announced itself.

    Raises:
        NotaryError: The child did not announce itself, or reported another key.
    """
    expected = notary_public_key(key)
    directory = tempfile.mkdtemp()
    try:
        path = os.path.join(directory, "notary.key")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(key.hex())
        process = subprocess.Popen(  # noqa: S603
            [binary, "notary", "--listen", listen, "--key-file", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        line = _first_line(process)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    try:
        announced = json.loads(line)
        reported = announced["notary_key"]
        address = announced["listening"]
        if not isinstance(reported, str) or not isinstance(address, str):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        _kill(process)
        raise NotaryError("notary: did not start") from None
    if reported != expected:
        _kill(process)
        raise NotaryError("notary: key mismatch")
    return Notary(process, address, reported)
