"""Canonical message construction and HMAC-SHA256 helpers."""

from __future__ import annotations

import hashlib
import hmac
import re


_EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


def build_canonical(timestamp: str, event_id: str, body: bytes) -> bytes:
    """Return the exact byte sequence defined by the webhook API contract."""
    if not isinstance(timestamp, str) or not timestamp:
        raise ValueError("timestamp must be a non-empty string")
    if not timestamp.isascii():
        raise ValueError("timestamp must contain ASCII characters only")
    if not isinstance(event_id, str) or not _EVENT_ID_PATTERN.fullmatch(event_id):
        raise ValueError("event_id must be 8-64 ASCII letters, digits, '_' or '-'")
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")

    return (
        timestamp.encode("ascii")
        + b"."
        + event_id.encode("ascii")
        + b"."
        + body
    )


def compute_signature(secret: bytes, canonical: bytes) -> str:
    """Compute a lowercase hexadecimal HMAC-SHA256 signature."""
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("secret must be non-empty bytes")
    if not isinstance(canonical, bytes):
        raise TypeError("canonical must be bytes")
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


def verify_signature(secret: bytes, canonical: bytes, received_hex: str) -> bool:
    """Compare a received hexadecimal signature in constant time."""
    if not isinstance(received_hex, str):
        return False
    if len(received_hex) != hashlib.sha256().digest_size * 2:
        return False
    try:
        int(received_hex, 16)
    except ValueError:
        return False

    expected = compute_signature(secret, canonical)
    return hmac.compare_digest(expected, received_hex)
