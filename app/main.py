"""WebhookGuard receiver - application entrypoint (task T04, owner: Devanshi Mehta).

    python -m app.main          # start the protected receiver + dashboard

Builds the Flask app from app/config.load_config(), wires the event store and
timestamp window into the decision engine, and mounts:

    POST /webhook        receiver/pipeline/endpoint.py  (contract section 1/4)
    GET  /dashboard      logs-dashboard/dashboard.py    (security dashboard page)
    GET  /api/dashboard  logs-dashboard/dashboard.py    (log data for the page)
    GET  /api/health     logs-dashboard/dashboard.py    (real status only)
"""
from __future__ import annotations

import os

from flask import Flask

from app.config import load_config
from app.wg_modules import get_dashboard
from receiver.pipeline.decision_engine import configure as configure_engine
from receiver.pipeline.endpoint import bp as webhook_bp
from store.event_store import create_event_store


def create_app() -> Flask:
    config = load_config()

    app = Flask(__name__, static_folder=None)  # static handled by dashboard routes

    # One event store for the whole process; engine fails closed if it is down.
    store = create_event_store(
        config.event_store,
        path=config.sqlite_path,
        redis_url=config.redis_url,
    )
    configure_engine(store=store, timestamp_window=config.timestamp_window)

    # Register blueprints. dashboard.py reads the same LOG_PATH logger.py writes.
    os.environ.setdefault("LOG_PATH", config.log_path)
    app.register_blueprint(webhook_bp)
    app.register_blueprint(get_dashboard().bp)

    @app.get("/")
    def index():
        return "<a href='/dashboard'>Webhook Security Dashboard</a>", 200

    return app


def main() -> None:
    app = create_app()
    # PORT/HOST are dev conveniences; the receiver itself is the standard 5000.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    print(f"WebhookGuard receiver listening on http://{host}:{port}")
    print(f"Dashboard: http://{host}:{port}/dashboard")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
