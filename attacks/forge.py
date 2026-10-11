
"""T15: Send a forged request signed with an unknown secret."""

import hashlib
import hmac
import time

from attacks.common import (
    PROTECTED_URL,
    new_event_id,
    payment_body,
    send_request,
    expect_invalid_signature,
)
from keys.key_manager import get_signing_key
from receiver.crypto.hmac_utils import build_canonical


def main() -> None:
    key_id, _real_secret = get_signing_key()

    timestamp = str(int(time.time()))
    event_id = new_event_id()
    body = payment_body(500)

    canonical = build_canonical(timestamp, event_id, body)

    forged_secret = b"attacker-controlled-wrong-secret"
    forged_hex = hmac.new(
        forged_secret,
        canonical,
        hashlib.sha256,
    ).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Event-Id": event_id,
        "X-Webhook-Key-Id": key_id,
        "X-Webhook-Signature": "sha256=" + forged_hex,
    }

    print("Attack: forged HMAC using an incorrect secret")
    print(f"Target: {PROTECTED_URL}")

    status, response_body = send_request(
        headers,
        body,
        "forgery",
    )

    expect_invalid_signature(
        status,
        response_body,
        "Forgery attack",
    )


if __name__ == "__main__":
    main()
