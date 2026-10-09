"""Create and send signed WebhookGuard requests."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass

import requests

from keys.key_manager import get_signing_key
from receiver.crypto.hmac_utils import build_canonical, compute_signature

DEFAULT_TIMEOUT = 10.0


@dataclass(frozen=True)
class SignedWebhook:
    """A webhook request with a body and headers ready to send unchanged."""

    event_id: str
    timestamp: str
    body: bytes
    headers: dict[str, str]


@dataclass(frozen=True)
class SendResult:
    """Metadata and HTTP response for a successfully transmitted webhook."""

    event_id: str
    timestamp: str
    response: requests.Response


class WebhookSendError(Exception):
    """A transport error raised after a request could not be sent."""

    def __init__(self, message: str, event_id: str, timestamp: str) -> None:
        super().__init__(message)
        self.event_id = event_id
        self.timestamp = timestamp


def create_signed_webhook(payload: dict[str, object]) -> SignedWebhook:
    """Serialize, canonicalize, and sign a payload for the active key."""
    timestamp = str(int(time.time()))
    event_id = f"evt_{uuid.uuid4().hex}"
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    key_id, secret = get_signing_key()
    canonical = build_canonical(timestamp, event_id, body)
    signature = compute_signature(secret, canonical)
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Event-Id": event_id,
        "X-Webhook-Key-Id": key_id,
        "X-Webhook-Signature": f"sha256={signature}",
    }
    return SignedWebhook(event_id, timestamp, body, headers)


def send_webhook(
    payload: dict[str, object],
    receiver_url: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> SendResult:
    """Sign and POST a webhook, raising a safe error for transport failures.

    HTTP error responses are returned normally so callers can display the
    receiver's status and response body.
    """
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    signed = create_signed_webhook(payload)
    try:
        response = requests.post(
            receiver_url,
            data=signed.body,
            headers=signed.headers,
            timeout=timeout,
        )
    except requests.exceptions.Timeout as exc:
        raise WebhookSendError(
            "The request timed out while waiting for the receiver.",
            signed.event_id,
            signed.timestamp,
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise WebhookSendError(
            "Could not connect to the receiver.",
            signed.event_id,
            signed.timestamp,
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise WebhookSendError(
            "The webhook request could not be sent.",
            signed.event_id,
            signed.timestamp,
        ) from exc

    return SendResult(signed.event_id, signed.timestamp, response)
