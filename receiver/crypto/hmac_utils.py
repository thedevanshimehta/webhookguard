
from __future__ import annotations

import hashlib
import hmac
import re

SIGNATURE_PREFIX = "sha256="
_EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


def build_canonical(timestamp: str, event_id: str, body: bytes) -> bytes:
    if not isinstance(timestamp, str) or not timestamp.isascii() or not timestamp:
        raise ValueError("Invalid timestamp")
    if not isinstance(event_id, str) or not _EVENT_ID_PATTERN.fullmatch(event_id):
        raise ValueError("Invalid event_id")
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    return timestamp.encode() + b"." + event_id.encode() + b"." + body


def compute_signature(secret: bytes, canonical: bytes) -> str:
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("Invalid secret")
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


def verify_signature(secret: bytes, canonical: bytes, received_hex: str) -> bool:
    if not isinstance(received_hex, str):
        return False
    received_hex = received_hex.strip().lower()
    expected = compute_signature(secret, canonical)
    return hmac.compare_digest(expected, received_hex)


def strip_signature_prefix(signature_header: str) -> str:
    header = (signature_header or "").strip()
    if header.lower().startswith(SIGNATURE_PREFIX):
        return header[len(SIGNATURE_PREFIX):].strip()
    return header
