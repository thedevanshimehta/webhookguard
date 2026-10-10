"""HMAC signature verification for incoming webhooks."""

from __future__ import annotations

import re

from keys import key_manager
from receiver.crypto.hmac_utils import build_canonical, verify_signature
from receiver.pipeline.result import (
    CheckResult,
    INVALID_SIGNATURE,
    MALFORMED,
    UNKNOWN_KEY,
    VALID,
)

_SIGNATURE_RE = re.compile(r"^sha256=([0-9a-f]{64})$")


def check_signature(
    key_id: str,
    timestamp: str,
    event_id: str,
    body: bytes,
    signature_header: str,
) -> CheckResult:
    """Verify the signature header against the exact request bytes.

    Header parsing and key lookup are deliberately performed before HMAC
    verification so callers can distinguish malformed requests and retired
    keys from forged or tampered requests.
    """
    if not all(isinstance(value, str) and value for value in (key_id, timestamp, event_id)):
        return CheckResult(False, MALFORMED)
    if not isinstance(body, bytes) or not isinstance(signature_header, str):
        return CheckResult(False, MALFORMED)

    match = _SIGNATURE_RE.fullmatch(signature_header)
    if match is None:
        return CheckResult(False, MALFORMED)

    try:
        secret = key_manager.get_key(key_id)
    except (TypeError, ValueError):
        return CheckResult(False, MALFORMED)
    if secret is None:
        return CheckResult(False, UNKNOWN_KEY)

    try:
        canonical = build_canonical(timestamp, event_id, body)
        valid = verify_signature(secret, canonical, match.group(1))
    except (TypeError, ValueError):
        return CheckResult(False, MALFORMED)

    return CheckResult(valid, VALID if valid else INVALID_SIGNATURE)
