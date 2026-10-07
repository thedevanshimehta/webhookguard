"""Canonicalization and HMAC utilities (task T07, owner: Laxmi Angadi).

Interface defined in docs/api-contract.md section 8. Signing rule (section 2):

    canonical  = timestamp + "." + event_id + "." + raw_body_bytes
    signature  = HMAC-SHA256(secret, canonical) -> lowercase hex

The body bytes are used exactly as received - never parse and re-dump the
JSON before verifying. Comparison is constant-time (hmac.compare_digest).

Test vector from contract section 2 (used by unit tests):
    secret     = "test-secret"
    timestamp  = "1727445520"
    event_id   = "evt_12345"
    body       = '{"event":"payment.success","amount":500,"currency":"INR"}'
    signature  = ab0d1dd6b5aa74d4b082edd7a61a2d42e09e36173303fcccf2657f47a3265f2a
"""
from __future__ import annotations

import hashlib
import hmac

SIGNATURE_PREFIX = "sha256="


def build_canonical(timestamp: str, event_id: str, body: bytes) -> bytes:
    """timestamp + "." + event_id + "." + raw_body_bytes (exactly as sent)."""
    if not isinstance(timestamp, str) or not isinstance(event_id, str):
        raise TypeError("timestamp and event_id must be strings")
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("body must be raw bytes")
    return timestamp.encode("ascii") + b"." + event_id.encode("ascii") + b"." + bytes(body)


def compute_signature(secret: bytes, canonical: bytes) -> str:
    """Lowercase hex HMAC-SHA256 of canonical under secret."""
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise ValueError("secret must be non-empty bytes")
    return hmac.new(bytes(secret), bytes(canonical), hashlib.sha256).hexdigest()


def verify_signature(secret: bytes, canonical: bytes, received_hex: str) -> bool:
    """Constant-time compare. `received_hex` has the 'sha256=' prefix removed."""
    if not isinstance(received_hex, str):
        return False
    expected = compute_signature(secret, canonical)
    return hmac.compare_digest(expected, received_hex.strip().lower())


def strip_signature_prefix(signature_header: str) -> str:
    """Remove the leading 'sha256=' from the X-Webhook-Signature header value."""
    header = (signature_header or "").strip()
    if header.lower().startswith(SIGNATURE_PREFIX):
        return header[len(SIGNATURE_PREFIX):].strip()
    return header
