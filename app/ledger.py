"""Demo application behind the protected receiver.

WebhookGuard forwards every accepted event here. It records payments in memory
so the demo can show the same /ledger view as the vulnerable receiver: after
the four attacks it holds only the genuine payments.
"""

from __future__ import annotations

import threading

from receiver.pipeline.result import Decision


class PaymentLedger:
    """Thread-safe in-memory list of processed events."""

    def __init__(self) -> None:
        self._entries: list[dict] = []
        self._lock = threading.Lock()

    def handle(self, payload: dict, decision: Decision) -> None:
        """Webhook handler: act on one verified event."""
        entry = {
            "event_id": decision.event_id,
            "event": payload.get("event"),
            "amount": payload.get("amount"),
            "currency": payload.get("currency"),
            "order_id": payload.get("order_id"),
        }
        with self._lock:
            self._entries.append(entry)

    def snapshot(self) -> dict:
        with self._lock:
            entries = list(self._entries)
        amounts = [e["amount"] for e in entries if isinstance(e["amount"], (int, float))]
        return {"count": len(entries), "total_amount": sum(amounts), "entries": entries}

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()
