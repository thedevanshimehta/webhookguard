"""Decision engine (task T14, owner: Harsh Ghole).

Runs the pipeline in the contract's fixed order (docs/api-contract.md section 3)
and stops at the first failure:

    1. parse/validate headers + body     -> malformed         (400)
    2. key lookup + signature check      -> unknown_key / invalid_signature (401)
    3. timestamp check                   -> expired           (400)
    4. replay check (records event_id!)  -> replayed          (409)
    5. accept                            -> valid             (200)

The event_id is stored ONLY after signature + timestamp pass, so unauthenticated
junk can never burn real event IDs (see store/event_store.py and
receiver/pipeline/replay_check.py for why).

The engine calls the security logger (logs-dashboard/logger.py) exactly once per
request and returns a Decision per contract section 8. The cryptographic checks
are the authority; nothing here interprets or re-orders them.
"""
from __future__ import annotations

import json
import re

from receiver.pipeline import replay_check
from receiver.pipeline.result import (Decision, HTTP_STATUS, VALID)
from receiver.pipeline.signature_check import check_signature
from receiver.pipeline.timestamp_check import check_timestamp
from store.event_store import EventStore

EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")  # contract section 1

# Injected by app/main.py at startup so the engine stays config-independent.
_event_store: EventStore | None = None
_timestamp_window: int = 300  # contract default; app/config.py overrides


def configure(store: EventStore, timestamp_window: int = 300) -> None:
    """Wire the engine to the event store and window chosen by app/config.py."""
    global _event_store, _timestamp_window
    _event_store = store
    _timestamp_window = timestamp_window


def verify_webhook(headers: dict, body: bytes, source_ip: str,
                   store: EventStore | None = None) -> Decision:
    """Verify one webhook request and return the Decision. Logs every decision."""
    from app.wg_modules import get_logger  # logs-dashboard/logger.py (hyphenated dir)

    def finish(reason: str, event_id: str | None, key_id: str | None,
               request_ts: int | None) -> Decision:
        accepted = reason == VALID
        decision = Decision(accepted, reason, HTTP_STATUS.get(reason, 400),
                            event_id, key_id)
        get_logger().log_decision(decision, source_ip, request_ts,
                                  bytes(body) if body else None)
        return decision

    # -- 1. Parse and validate headers and body (contract section 3 step 1) ----
    if not isinstance(headers, dict) or not isinstance(body, (bytes, bytearray)):
        return finish("malformed", None, None, None)

    timestamp_raw = headers.get("X-Webhook-Timestamp")
    event_id = headers.get("X-Webhook-Event-Id")
    key_id = headers.get("X-Webhook-Key-Id")
    signature = headers.get("X-Webhook-Signature")

    event_id_val = event_id if isinstance(event_id, str) and event_id else None
    key_id_val = key_id if isinstance(key_id, str) and key_id else None

    ts_int: int | None = None
    try:
        ts_str = str(timestamp_raw).strip()
        ts_int = int(ts_str)
        if ts_int < 0 or str(ts_int) != ts_str:  # reject "1e9", "12.5", "+5"
            raise ValueError
    except (TypeError, ValueError):
        return finish("malformed", event_id_val, key_id_val, None)

    if not isinstance(event_id, str) or not EVENT_ID_PATTERN.match(event_id):
        return finish("malformed", event_id_val, key_id_val, None)

    if key_id_val is None:
        return finish("malformed", event_id_val, None, None)

    try:
        json.loads(bytes(body).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return finish("malformed", event_id_val, key_id_val, None)

    if not isinstance(signature, str) or not signature.strip():
        return finish("malformed", event_id_val, key_id_val, None)

    # -- 2. Key lookup + signature check ---------------------------------------
    sig_result = check_signature(key_id_val, ts_str, event_id_val, bytes(body), signature)
    if not sig_result.ok:
        return finish(sig_result.reason, event_id_val, key_id_val, ts_int)

    # -- 3. Timestamp check ------------------------------------------------------
    ts_result = check_timestamp(ts_int, window=_timestamp_window)
    if not ts_result.ok:
        return finish(ts_result.reason, event_id_val, key_id_val, ts_int)

    # -- 4. Replay check: records the event_id atomically; fails closed (503) ---
    store_to_use = store or _event_store
    if store_to_use is None:
        return finish("store_unavailable", event_id_val, key_id_val, ts_int)

    replay = replay_check.check_replay(
        event_id_val, store_to_use,
        window_seconds=_timestamp_window,
        future_skew_seconds=_timestamp_window,
        key_id=key_id_val,
    )
    if not replay.passed:
        return finish(replay.reason, event_id_val, key_id_val, ts_int)

    # -- 5. Accept ----------------------------------------------------------------
    return finish(VALID, event_id_val, key_id_val, ts_int)
