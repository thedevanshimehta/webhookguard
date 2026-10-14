"""Entrypoint for the protected WebhookGuard receiver (T04).

    python -m app.main                  # http://127.0.0.1:5000

Routes:
    POST /webhook          verified webhooks (see docs/api-contract.md)
    GET  /dashboard        security dashboard (reads LOG_PATH)
    GET  /dashboard/data   dashboard data as JSON
    GET  /ledger           payments the application has processed
    POST /reset            clear the ledger between demo runs

Settings come from .env (see .env.example). HOST and PORT choose where to
listen; the default is loopback only. The Flask development server is used,
which is fine for the demo; a real deployment would run behind a production
WSGI server with HTTPS.
"""

from __future__ import annotations

import os
import sys

from flask import Flask, jsonify

from app.config import load_config
from app.ledger import PaymentLedger
from keys.key_manager import KeyConfigError, get_signing_key
from receiver.pipeline.endpoint import create_webhook_app

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


def create_app() -> Flask:
    """Build the protected receiver with the demo payment ledger attached."""
    ledger = PaymentLedger()
    app = create_webhook_app(handler=ledger.handle)
    app.extensions["webhookguard_ledger"] = ledger

    @app.get("/ledger")
    def get_ledger():
        return jsonify(ledger.snapshot())

    @app.post("/reset")
    def reset():
        ledger.reset()
        return jsonify({"status": "reset"})

    return app


def main() -> int:
    try:
        config = load_config()
        key_id, _secret = get_signing_key()  # fail fast on a missing or placeholder key
    except (KeyConfigError, ValueError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    host = os.environ.get("HOST", DEFAULT_HOST)
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    app = create_app()

    print(f"WebhookGuard protected receiver on http://{host}:{port}")
    print(f"  webhook:   POST /webhook   (signing key id: {key_id})")
    print(f"  dashboard: http://{host}:{port}/dashboard")
    print(f"  event store: {config.event_store} | log: {config.log_path}")
    app.run(host=host, port=port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
