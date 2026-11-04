"""Where the bank credential lives, and how it is kept out of other processes."""

from collections.abc import Mapping, MutableMapping

BANK_KEY_ENV = "INCREASE_SANDBOX_API_KEY"


def take_bank_key(env: MutableMapping[str, str]) -> str | None:
    """Remove the bank key from an environment and return it.

    Args:
        env: Environment to take the key from, usually ``os.environ``.

    Returns:
        The key, or None when it is missing or empty.
    """
    return env.pop(BANK_KEY_ENV, None) or None


def without_bank_key(env: Mapping[str, str]) -> dict[str, str]:
    """Copy an environment without the bank key, for a process that must not hold it.

    Args:
        env: Environment to copy.

    Returns:
        The copy.
    """
    return {name: value for name, value in env.items() if name != BANK_KEY_ENV}
