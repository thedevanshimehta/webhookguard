"""Signature verification step (task T10, owner: Vedansh Gholba).

Contract docs/api-contract.md section 8:
    check_signature(key_id, timestamp, event_id, body, signature_header) -> CheckResult

Strips the "sha256=" prefix, looks the secret up in the key manager (supporting
rotation: any configured key may verify), rebuilds the canonical message and
compares in constant time.

Reason codes: "valid" (200) | "unknown_key" (401) | "invalid_signature" (401).
The receiver cannot cryptographically tell a forged request (bogus signature,
never had the key) from a tampered one (valid request with modified bytes) -
both fail the HMAC, so the contract uses one code, invalid_signature.
"""
from __future__ import annotations

from keys import key_manager
from receiver.crypto.hmac_utils import (build_canonical, compute_signature,
                                        strip_signature_prefix)
from receiver.pipeline.result import (CheckResult, HTTP_STATUS, INVALID_SIGNATURE,
                                      UNKNOWN_KEY, VALID)


def check_signature(key_id: str, timestamp: str, event_id: str,
                    body: bytes, signature_header: str) -> CheckResult:
    """Verify X-Webhook-Signature over timestamp.event_id.body for any active key."""
    secret = key_manager.get_key(key_id)
    if secret is None:
        return CheckResult(False, UNKNOWN_KEY)

    try:
        canonical = build_canonical(timestamp, event_id, body)
        received_hex = strip_signature_prefix(signature_header)
        expected_hex = compute_signature(secret, canonical)
    except (TypeError, ValueError):
        return CheckResult(False, INVALID_SIGNATURE)

    # hmac_utils.verify_signature already does a constant-time compare; use the
    # precomputed expected value to report UNKNOWN_KEY vs INVALID_SIGNATURE cleanly.
    import hmac as _hmac
    if _hmac.compare_digest(expected_hex, received_hex.lower()):
        return CheckResult(True, VALID)
    return CheckResult(False, INVALID_SIGNATURE)
