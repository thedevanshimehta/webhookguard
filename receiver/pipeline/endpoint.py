"""Flask adapter for the protected webhook endpoint."""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from collections.abc import Callable

from flask import Blueprint, Flask, jsonify, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge

from receiver.pipeline.result import (
    Decision,
    HTTP_STATUS,
    PROCESSING_FAILED,
    TOO_LARGE,
)

Verifier = Callable[[dict[str, str], bytes, str], Decision]
# The application: called once for every accepted event with the parsed JSON
# payload. Raising an exception means the event was NOT processed.
Handler = Callable[[dict, Decision], None]
# Called when the handler raises; returns the decision to send back.
FailureHook = Callable[[Decision], Decision]

log = logging.getLogger("webhookguard.endpoint")

DEFAULT_MAX_BODY_BYTES = 1024 * 1024
DASHBOARD_HTML = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                 "logs-dashboard", "dashboard.html")
)
DASHBOARD_RECENT_ENTRIES = 200


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


def _processing_failed(decision: Decision) -> Decision:
    return Decision(
        accepted=False,
        reason=PROCESSING_FAILED,
        http_status=HTTP_STATUS[PROCESSING_FAILED],
        event_id=decision.event_id,
        key_id=decision.key_id,
    )


def create_webhook_blueprint(
    verifier: Verifier | None = None,
    handler: Handler | None = None,
    on_handler_error: FailureHook | None = None,
) -> Blueprint:
    """Create the ``POST /webhook`` route with an optional verifier override.

    If a handler is given, every accepted event is passed to it. When the
    handler raises, on_handler_error decides the response (default: 500
    processing_failed), so the sender knows to retry.
    """
    blueprint = Blueprint("webhook", __name__)

    @blueprint.post("/webhook")
    def webhook():
        verify = verifier or _default_verifier()
        headers = {key: value for key, value in request.headers.items()}
        body = request.get_data(cache=True, as_text=False)
        decision = verify(headers, body, request.remote_addr or "")
        if decision.accepted and handler is not None:
            try:
                handler(json.loads(body), decision)
            except Exception:
                log.exception("application failed to process event %s", decision.event_id)
                decision = (on_handler_error or _processing_failed)(decision)
        return _response_for(decision)

    return blueprint


def create_webhook_app(
    verifier: Verifier | None = None,
    handler: Handler | None = None,
    dashboard: bool = True,
) -> Flask:
    """Create the Flask app and initialize the shared event store once.

    With the default verifier, configuration is loaded once here and shared by
    every request. The app then also serves the security dashboard at
    ``GET /dashboard`` (data at ``GET /dashboard/data``) unless dashboard=False.
    """
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = DEFAULT_MAX_BODY_BYTES
    config = None
    on_handler_error = None

    if verifier is None:
        from app.config import load_config
        from store.event_store import create_event_store
        from receiver.pipeline.decision_engine import verify_webhook
        from receiver.pipeline.replay_check import release_replay
        from receiver.pipeline.security_log import log_decision

        config = load_config()
        app.config["MAX_CONTENT_LENGTH"] = config.max_body_bytes

        # Create one store for this application instance.
        event_store = create_event_store(
            kind=config.event_store,
            path=config.event_store_path,
            redis_url=config.redis_url,
        )

        # Keep a reference to the store for application-level access.
        app.extensions["webhookguard_event_store"] = event_store
        app.extensions["webhookguard_config"] = config

        # Pass the same store and config to every request's verification pipeline.
        def configured_verifier(headers, body, source_ip):
            return verify_webhook(
                headers,
                body,
                source_ip,
                event_store=event_store,
                config=config,
            )

        verifier = configured_verifier

        def release_and_log(decision: Decision) -> Decision:
            # The event was recorded by the replay check but never processed.
            # Forget it so the sender's retry is accepted instead of "replayed".
            release_replay(decision.event_id, event_store, key_id=decision.key_id)
            failed = _processing_failed(decision)
            log_decision(failed, request.remote_addr or "", None,
                         request.get_data(cache=True), config.log_path)
            return failed

        on_handler_error = release_and_log

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        decision = Decision(
            accepted=False,
            reason=TOO_LARGE,
            http_status=HTTP_STATUS[TOO_LARGE],
            event_id=request.headers.get("X-Webhook-Event-Id"),
            key_id=request.headers.get("X-Webhook-Key-Id"),
        )
        if config is not None:
            from receiver.pipeline.security_log import log_decision
            log_decision(decision, request.remote_addr or "", None, None, config.log_path)
        return _response_for(decision)

    app.register_blueprint(create_webhook_blueprint(verifier, handler, on_handler_error))

    if dashboard and config is not None:
        _register_dashboard(app, config.log_path)

    return app


def _register_dashboard(app: Flask, log_path: str) -> None:
    from receiver.pipeline.security_log import read_log

    @app.get("/dashboard")
    def dashboard_page():
        return send_file(DASHBOARD_HTML, mimetype="text/html")

    @app.get("/dashboard/data")
    def dashboard_data():
        entries = read_log(log_path)
        counts = Counter(entry.get("reason") for entry in entries)
        return jsonify({
            "total": len(entries),
            "accepted": sum(1 for e in entries if e.get("decision") == "accepted"),
            "counts": dict(counts),
            "recent": entries[-DASHBOARD_RECENT_ENTRIES:][::-1],
        })


__all__ = ["create_webhook_app", "create_webhook_blueprint"]
