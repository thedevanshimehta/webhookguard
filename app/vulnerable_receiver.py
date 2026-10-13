"""DELIBERATELY VULNERABLE webhook receiver (T12). DEMO USE ONLY.

This receiver trusts every request. It does NOT check signatures, timestamps
or event IDs, so forged, tampered, replayed and expired webhooks are all
accepted. It exists so the demo can show the same attacks succeeding here
and being rejected by the protected receiver (receiver/pipeline/endpoint.py).

Safeguards:
  * Binds to 127.0.0.1 only. There is no option to expose it to a network.
  * Never reads WEBHOOKGUARD_KEYS or any other secret.
  * Is not imported by app/main.py and must never be.
  * Keeps its "application state" in memory only (nothing is written to disk).

Run it (separate terminal from the protected receiver on port 5000):

    python -m app.vulnerable_receiver            # http://127.0.0.1:5001

Set VULNERABLE_PORT to change the port.

Besides POST /webhook it exposes two demo helpers:
    GET  /ledger   -> what the "application" has acted on so far
    POST /reset    -> clear the ledger between demo runs
"""

from __future__ import annotations

import os
import threading

from flask import Flask, jsonify, request

HOST = "127.0.0.1"  # loopback only, on purpose
DEFAULT_PORT = 5001

BANNER = r"""
=====================================================================
  WARNING: VULNERABLE RECEIVER - DEMO ONLY
  No signature, timestamp or replay checks. Every request is trusted.
  Listening on {host}:{port} (loopback only). Do not deploy this.
=====================================================================
"""


def create_app() -> Flask:
    """Build the vulnerable Flask app. Each call has its own empty ledger."""
    app = Flask(__name__)
    ledger: list[dict] = []
    lock = threading.Lock()

    @app.post("/webhook")
    def webhook():
        # The only validation: the body must be JSON so there is something to act on.
        # Headers (signature, timestamp, event id, key id) are never inspected.
        payload = request.get_json(silent=True)
        event_id = request.headers.get("X-Webhook-Event-Id")
        if not isinstance(payload, dict):
            return (
                jsonify({"status": "rejected", "reason": "malformed", "event_id": event_id}),
                400,
            )

        entry = {
            "event_id": event_id,
            "event": payload.get("event"),
            "amount": payload.get("amount"),
            "currency": payload.get("currency"),
            "order_id": payload.get("order_id"),
        }
        with lock:
            ledger.append(entry)
            count = len(ledger)

        print(
            f"[VULNERABLE] ACCEPTED #{count} event={entry['event']} "
            f"amount={entry['amount']} {entry['currency']} event_id={event_id}",
            flush=True,
        )
        return jsonify({"status": "accepted", "reason": "valid", "event_id": event_id}), 200

    @app.get("/ledger")
    def get_ledger():
        with lock:
            entries = list(ledger)
        amounts = [e["amount"] for e in entries if isinstance(e["amount"], (int, float))]
        return jsonify(
            {"count": len(entries), "total_amount": sum(amounts), "entries": entries}
        )

    @app.post("/reset")
    def reset():
        with lock:
            ledger.clear()
        return jsonify({"status": "reset"})

    return app


def main() -> None:
    port = int(os.environ.get("VULNERABLE_PORT", DEFAULT_PORT))
    print(BANNER.format(host=HOST, port=port))
    create_app().run(host=HOST, port=port, debug=False)


if __name__ == "__main__":
    main()
