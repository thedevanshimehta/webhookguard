"""Flask adapter for the protected webhook endpoint."""

from __future__ import annotations

from collections.abc import Callable

from flask import Blueprint, Flask, jsonify, request

from receiver.pipeline.result import Decision

Verifier = Callable[[dict[str, str], bytes, str], Decision]


def _response_for(decision: Decision):
    payload = {
        "status": "accepted" if decision.accepted else "rejected",
        "reason": decision.reason,
        "event_id": decision.event_id,
    }
    return jsonify(payload), decision.http_status


def _default_verifier() -> Verifier:
    try:
        from receiver.pipeline.decision_engine import verify_webhook
    except ImportError as exc:
        raise RuntimeError(
            "receiver.pipeline.decision_engine.verify_webhook is required "
            "to serve the webhook endpoint"
        ) from exc
    return verify_webhook


def create_webhook_blueprint(verifier: Verifier | None = None) -> Blueprint:
    """Create the ``POST /webhook`` route with an optional verifier override."""
    blueprint = Blueprint("webhook", __name__)

    @blueprint.post("/webhook")
    def webhook():
        verify = verifier or _default_verifier()
        headers = {key: value for key, value in request.headers.items()}
        body = request.get_data(cache=True, as_text=False)
        decision = verify(headers, body, request.remote_addr or "")
        return _response_for(decision)

    return blueprint


def create_webhook_app(verifier: Verifier | None = None) -> Flask:
    """Create a small Flask app exposing the protected webhook route."""
    app = Flask(__name__)
    app.register_blueprint(create_webhook_blueprint(verifier))
    return app


__all__ = ["create_webhook_app", "create_webhook_blueprint"]
