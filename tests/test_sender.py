import re
from unittest.mock import Mock

import pytest
import requests

from receiver.crypto.hmac_utils import build_canonical, compute_signature
from sender import sender
from sender.cli import (
    DEFAULT_RECEIVER_URL,
    build_payment_event,
    main,
    parse_args,
)


SECRET = b"test-secret"


@pytest.fixture
def signing_key(monkeypatch):
    monkeypatch.setenv("WEBHOOKGUARD_KEYS", "k1:test-secret")


def test_signed_webhook_has_unique_ids_and_unix_timestamps(signing_key):
    first = sender.create_signed_webhook({"event": "payment.success"})
    second = sender.create_signed_webhook({"event": "payment.success"})

    assert first.event_id.startswith("evt_")
    assert re.fullmatch(r"evt_[0-9a-f]{32}", first.event_id)
    assert first.event_id != second.event_id
    assert first.timestamp.isascii() and first.timestamp.isdigit()
    assert abs(int(first.timestamp) - int(sender.time.time())) <= 1


def test_signed_webhook_uses_exact_compact_body_for_canonical_and_signature(signing_key):
    signed = sender.create_signed_webhook(
        {"event": "payment.success", "amount": 500, "currency": "INR"}
    )

    assert signed.body == (
        b'{"event":"payment.success","amount":500,"currency":"INR"}'
    )
    canonical = build_canonical(signed.timestamp, signed.event_id, signed.body)
    assert canonical == (
        signed.timestamp.encode()
        + b"."
        + signed.event_id.encode()
        + b"."
        + signed.body
    )
    assert signed.headers["X-Webhook-Signature"] == (
        "sha256=" + compute_signature(SECRET, canonical)
    )
    assert re.fullmatch(r"sha256=[0-9a-f]{64}", signed.headers["X-Webhook-Signature"])


def test_send_webhook_posts_signed_raw_body_and_exact_headers(signing_key, monkeypatch):
    response = Mock(spec=requests.Response)
    monkeypatch.setattr(sender.requests, "post", Mock(return_value=response))

    result = sender.send_webhook(
        {"event": "payment.success", "amount": 500}, "http://localhost:5000/webhook"
    )

    call = sender.requests.post.call_args
    assert call.args == ("http://localhost:5000/webhook",)
    assert call.kwargs["data"] == b'{"event":"payment.success","amount":500}'
    assert "json" not in call.kwargs
    assert call.kwargs["timeout"] == sender.DEFAULT_TIMEOUT
    assert call.kwargs["headers"] == {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": result.timestamp,
        "X-Webhook-Event-Id": result.event_id,
        "X-Webhook-Key-Id": "k1",
        "X-Webhook-Signature": (
            "sha256="
            + compute_signature(
                SECRET,
                build_canonical(
                    result.timestamp,
                    result.event_id,
                    call.kwargs["data"],
                ),
            )
        ),
    }
    assert result.response is response


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        (requests.exceptions.ConnectionError, "Could not connect"),
        (requests.exceptions.Timeout, "timed out"),
    ],
)
def test_send_webhook_wraps_connection_failures(
    signing_key, monkeypatch, exception, message
):
    monkeypatch.setattr(sender.requests, "post", Mock(side_effect=exception))

    with pytest.raises(sender.WebhookSendError, match=message) as error:
        sender.send_webhook({"event": "payment.success"}, DEFAULT_RECEIVER_URL)

    assert error.value.event_id.startswith("evt_")
    assert error.value.timestamp.isdigit()


def test_cli_arguments_and_sample_payment_event():
    args = parse_args(
        [
            "--event",
            "payment.success",
            "--amount",
            "500",
            "--currency",
            "INR",
            "--order-id",
            "order-123",
            "--url",
            "http://localhost:8080/webhook",
        ]
    )

    assert args.event == "payment.success"
    assert args.amount == 500
    assert args.currency == "INR"
    assert args.order_id == "order-123"
    assert args.url == "http://localhost:8080/webhook"
    assert build_payment_event(args.event, args.amount, args.currency, args.order_id) == {
        "event": "payment.success",
        "amount": 500,
        "currency": "INR",
        "order_id": "order-123",
    }
    assert parse_args([]).url == DEFAULT_RECEIVER_URL


def test_cli_displays_send_metadata_and_http_response(monkeypatch, capsys):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.text = '{"status":"accepted"}'
    result = sender.SendResult("evt_test123", "1727445520", response)
    monkeypatch.setattr("sender.cli.send_webhook", Mock(return_value=result))

    assert main(["--event", "payment.success", "--amount", "500"]) == 0

    output = capsys.readouterr().out
    assert "Event ID: evt_test123" in output
    assert "Timestamp: 1727445520" in output
    assert "HTTP status: 200" in output
    assert '{"status":"accepted"}' in output
