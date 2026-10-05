"""Key management and rotation (task T03, owner: Devanshi).

Interface is defined in docs/api-contract.md, section 8:
    get_key(key_id)        -> bytes | None
    get_active_keys()      -> dict[str, bytes]   (all keys valid for verification)
    get_signing_key()      -> tuple[str, bytes]  (key the sender signs with)

Configuration: environment variable WEBHOOKGUARD_KEYS, format
    "key_id:secret,key_id:secret,..."
- The FIRST entry is the active signing key.
- Remaining entries are still accepted for verification (rotation overlap).

Rotation procedure (no downtime):
    1. Before: WEBHOOKGUARD_KEYS="k1:<old>"
    2. Add the new key FIRST:  "k2:<new>,k1:<old>"   -> sender signs with k2, receiver accepts k1 and k2
    3. After the overlap period (senders all switched, e.g. 24h): "k2:<new>"   -> k1 is retired

Secrets are never hardcoded, never logged and never included in error messages.
"""
import os
import re
import secrets

ENV_VAR = "WEBHOOKGUARD_KEYS"
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
MIN_SECRET_LENGTH = 8  # absolute minimum; real secrets should come from generate_secret() (64 hex chars)


class KeyConfigError(ValueError):
    """Raised when WEBHOOKGUARD_KEYS is missing or malformed. Messages never contain secrets."""


def generate_secret(nbytes: int = 32) -> str:
    """Return a new random secret as a hex string (64 characters by default)."""
    return secrets.token_hex(nbytes)


def _load_keys() -> list[tuple[str, bytes]]:
    """Parse the environment into an ordered list of (key_id, secret_bytes). Order = priority."""
    raw = os.environ.get(ENV_VAR, "").strip()
    if not raw:
        raise KeyConfigError(f"{ENV_VAR} is not set. See .env.example.")

    keys: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for position, entry in enumerate(raw.split(","), start=1):
        entry = entry.strip()
        if not entry:
            continue
        key_id, sep, secret = entry.partition(":")  # split on first colon only
        if not sep:
            raise KeyConfigError(f"Entry {position} in {ENV_VAR} must look like key_id:secret.")
        if not KEY_ID_PATTERN.match(key_id):
            raise KeyConfigError(f"Entry {position}: key_id must be 1-32 chars of A-Z a-z 0-9 _ -.")
        if len(secret) < MIN_SECRET_LENGTH:
            raise KeyConfigError(f"Entry {position}: secret is shorter than {MIN_SECRET_LENGTH} characters.")
        if key_id in seen:
            raise KeyConfigError(f"Duplicate key_id '{key_id}' in {ENV_VAR}.")
        seen.add(key_id)
        keys.append((key_id, secret.encode("utf-8")))

    if not keys:
        raise KeyConfigError(f"{ENV_VAR} contains no keys.")
    return keys


def get_key(key_id: str) -> bytes | None:
    """Secret for key_id, or None if the key is unknown or retired."""
    for kid, secret in _load_keys():
        if kid == key_id:
            return secret
    return None


def get_active_keys() -> dict[str, bytes]:
    """All keys valid for verification: the signing key plus any still in the overlap period."""
    return dict(_load_keys())


def get_signing_key() -> tuple[str, bytes]:
    """(key_id, secret) the sender should sign with: the first configured key."""
    return _load_keys()[0]


if __name__ == "__main__":
    # Helper:  python -m keys.key_manager   -> prints a fresh secret to paste into .env
    print(generate_secret())