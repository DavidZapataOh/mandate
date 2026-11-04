"""Where the bank credential lives, and how it is kept out of other processes."""

from collections.abc import Mapping, MutableMapping

BANK_KEY_ENV = "INCREASE_SANDBOX_API_KEY"
# Every name an Increase credential goes by: the verifier's key, the holder's
# read key, the key the SDK itself reads, the webhook secret, and the secret
# the SDK itself reads. No agent process may hold any of them.
HOLDER_KEY_ENV = "INCREASE_HOLDER_API_KEY"
WEBHOOK_SECRET_ENV = "INCREASE_SANDBOX_WEBHOOK_SECRET"  # noqa: S105
BANK_KEY_NAMES = (
    BANK_KEY_ENV,
    HOLDER_KEY_ENV,
    "INCREASE_API_KEY",
    WEBHOOK_SECRET_ENV,
    "INCREASE_WEBHOOK_SECRET",
)


def take_bank_key(env: MutableMapping[str, str]) -> str | None:
    """Remove the bank key from an environment and return it.

    Args:
        env: Environment to take the key from, usually ``os.environ``.

    Returns:
        The key, or None when it is missing or empty.
    """
    return env.pop(BANK_KEY_ENV, None) or None


def take_holder_key(env: MutableMapping[str, str]) -> str | None:
    """Remove the holder's read key from an environment and return it.

    Args:
        env: Environment to take the key from, usually ``os.environ``.

    Returns:
        The key, or None when it is missing or empty.
    """
    return env.pop(HOLDER_KEY_ENV, None) or None


def take_webhook_secret(env: MutableMapping[str, str]) -> str | None:
    """Remove the secret the bank signs its webhooks with and return it.

    The name the SDK reads by default is removed too, so no child inherits it.

    Args:
        env: Environment to take the secret from, usually ``os.environ``.

    Returns:
        The pinned name's secret, or None when it is missing or empty.
    """
    env.pop("INCREASE_WEBHOOK_SECRET", None)
    return env.pop(WEBHOOK_SECRET_ENV, None) or None


def credential_exposed(env: Mapping[str, str]) -> bool:
    """Tell whether an environment holds an Increase key under any of its names.

    Args:
        env: Environment to look at.

    Returns:
        True when any name in ``BANK_KEY_NAMES`` is present, even if empty.
    """
    return any(name in env for name in BANK_KEY_NAMES)


def without_bank_key(env: Mapping[str, str]) -> dict[str, str]:
    """Copy an environment without any bank key, for a process that must not hold one.

    Args:
        env: Environment to copy.

    Returns:
        The copy, without any name in ``BANK_KEY_NAMES``.
    """
    return {name: value for name, value in env.items() if name not in BANK_KEY_NAMES}
