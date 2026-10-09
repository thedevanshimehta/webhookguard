"""Command-line interface for sending a sample WebhookGuard payment event."""

from __future__ import annotations

import argparse
import sys
import uuid
from typing import Sequence

import requests

from keys.key_manager import KeyConfigError
from sender.sender import SendResult, WebhookSendError, send_webhook

DEFAULT_RECEIVER_URL = "http://127.0.0.1:5000/webhook"


def build_payment_event(
    event: str,
    amount: int,
    currency: str,
    order_id: str | None = None,
) -> dict[str, object]:
    """Build a sample payment event payload for the CLI."""
    return {
        "event": event,
        "amount": amount,
        "currency": currency,
        "order_id": order_id or f"ord_{uuid.uuid4().hex}",
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Send a signed sample payment event to WebhookGuard."
    )
    parser.add_argument(
        "--event",
        default="payment.success",
        help="Event name (default: payment.success)",
    )
    parser.add_argument(
        "--amount",
        type=int,
        default=500,
        help="Payment amount as an integer (default: 500)",
    )
    parser.add_argument(
        "--currency",
        default="INR",
        help="Currency code (default: INR)",
    )
    parser.add_argument(
        "--order-id",
        help="Order identifier (generated if omitted)",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_RECEIVER_URL,
        help=f"Receiver webhook URL (default: {DEFAULT_RECEIVER_URL})",
    )
    return parser.parse_args(argv)


def _print_result(result: SendResult) -> int:
    response = result.response
    print(f"Event ID: {result.event_id}")
    print(f"Timestamp: {result.timestamp}")
    print(f"HTTP status: {response.status_code}")
    try:
        response_body = response.text
    except requests.exceptions.RequestException as exc:
        print(f"Could not read receiver response: {exc}", file=sys.stderr)
        return 1
    if response_body:
        print(f"Response: {response_body}")
    if response.status_code >= 400:
        print("The receiver rejected the webhook.", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the webhook sender CLI."""
    args = parse_args(argv)
    payload = build_payment_event(
        args.event,
        args.amount,
        args.currency,
        args.order_id,
    )

    try:
        result = send_webhook(payload, args.url)
    except WebhookSendError as exc:
        print(f"Event ID: {exc.event_id}")
        print(f"Timestamp: {exc.timestamp}")
        print(f"Error: {exc}", file=sys.stderr)
        print(
            "Check that the receiver is running and that --url is correct.",
            file=sys.stderr,
        )
        return 1
    except KeyConfigError as exc:
        print(f"Signing key configuration error: {exc}", file=sys.stderr)
        return 1

    return _print_result(result)


if __name__ == "__main__":
    raise SystemExit(main())
