"""Shared helpers for WebhookGuard attack demonstrations.

Run from the repository root:
    python -m attacks.forge
    python -m attacks.tamper
    python -m attacks.replay
    python -m attacks.expired
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid

from keys.key_manager import get_signing_key
from receiver.crypto.hmac_utils import build_canonical, compute_signature

PROTECTED_URL = os.getenv("WEBHOOKGUARD_URL", "http://127.0.0.1:5000/webhook")
TIMEOUT_SECONDS = float(os.getenv("WEBHOOKGUARD_TIMEOUT", "5"))


def new_event_id() -> str:
    return "evt_" + uuid.uuid4().hex


def make_request(body: bytes, timestamp: int | None = None, event_id: str | None = None):
    """Build a valid signed request using the currently configured signing key."""
    key_id, secret = get_signing_key()
    ts = str(int(time.time()) if timestamp is None else timestamp)
    eid = event_id or new_event_id()
    canonical = build_canonical(ts, eid, body)
    signature = compute_signature(secret, canonical)
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": ts,
        "X-Webhook-Event-Id": eid,
        "X-Webhook-Key-Id": key_id,
        "X-Webhook-Signature": "sha256=" + signature,
    }
    return headers, body


def send_request(headers: dict[str, str], body: bytes, label: str = "request") -> tuple[int, str]:
    """POST raw bytes and print the status/body, including non-2xx responses."""
    request = urllib.request.Request(
        PROTECTED_URL, data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
            response_body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        response_body = exc.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[{label}] Could not reach receiver at {PROTECTED_URL}: {exc}")
        print("Start the receiver and set WEBHOOKGUARD_URL if it uses another address.")
        return 0, str(exc)

    print(f"\n[{label}] HTTP {status}")
    try:
        print(json.dumps(json.loads(response_body), indent=2))
    except json.JSONDecodeError:
        print(response_body)
    return status, response_body


def payment_body(amount: int = 500) -> bytes:
    """Keep this JSON compact and deterministic for tampering demonstrations."""
    return json.dumps(
        {"event": "payment.success", "amount": amount, "currency": "INR"},
        separators=(",", ":"),
    ).encode("utf-8")

def expect_invalid_signature(
    status: int,
    response_body: str,
    label: str,
) -> None:
    """Fail the demonstration unless the receiver rejects the signature."""
    try:
        data = json.loads(response_body)
    except json.JSONDecodeError:
        data = {}

    if status == 401 and data.get("reason") == "invalid_signature":
        print(f"PASS: {label} rejected with invalid_signature")
        return

    print(
        f"FAIL: {label} expected HTTP 401 / invalid_signature, "
        f"received HTTP {status}, reason={data.get('reason')!r}"
    )
    raise SystemExit(1)