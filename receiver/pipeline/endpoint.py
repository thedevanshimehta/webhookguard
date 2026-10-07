"""Webhook endpoint (task T10, owner: Vedansh Gholba).

One Flask blueprint exposing contract section 1/4:

    POST /webhook  ->  {"status": "accepted"|"rejected",
                        "reason": <section 4 code>, "event_id": ...}

The raw request bytes are passed to the decision engine untouched - the
signature covers exactly these bytes (contract section 2), so parsing or
re-serialising before verification would break every signature.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from receiver.pipeline.decision_engine import verify_webhook
from receiver.pipeline.result import HTTP_STATUS, MALFORMED, VALID

bp = Blueprint("webhook", __name__)


@bp.post("/webhook")
def webhook():
    body = request.get_data()  # raw bytes, exactly as received

    # Header access is case-insensitive in Flask; normalise to the contract names.
    headers = {
        "X-Webhook-Timestamp": request.headers.get("X-Webhook-Timestamp"),
        "X-Webhook-Event-Id": request.headers.get("X-Webhook-Event-Id"),
        "X-Webhook-Key-Id": request.headers.get("X-Webhook-Key-Id"),
        "X-Webhook-Signature": request.headers.get("X-Webhook-Signature"),
    }
    source_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")

    decision = verify_webhook(headers, body, source_ip)

    response = jsonify({
        "status": "accepted" if decision.accepted else "rejected",
        "reason": decision.reason,
        "event_id": decision.event_id,
    })
    response.status_code = decision.http_status
    return response
