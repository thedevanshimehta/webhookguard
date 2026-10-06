"""Replay detection step of the verification pipeline.

Owner: Yashvi Dalal (T13).  Branch: feature/replay-check

Pipeline order (decision engine, T14, must keep this order):

    1. signature check   (T10)  -> 401 forged / tampered
    2. timestamp check   (T11)  -> 400 expired
    3. REPLAY CHECK      (this) -> 409 replayed
    4. accept            -> 200 valid

WHY LAST: check_and_set() *records* the event_id. If it ran before the
signature check, an attacker with no key could send junk requests with
guessed/future event_ids and "burn" them, so the real webhook with that ID
would later be rejected as a replay.  Only authenticated, fresh requests may
touch the store.

TTL: an event must be remembered for as long as it could still pass the
timestamp check.  The timestamp window accepts ts in [now - W, now + S]
(W = window, S = allowed future skew), so a request stamped at the far edge
stays acceptable until ts + W = now + S + W.  Remembering it for only W would
let an attacker replay it near the end.  ttl_for_window() therefore returns
W + S (+ small margin).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from store.event_store import EventStore, StoreUnavailable

log = logging.getLogger("webhookguard.replay")

DEFAULT_WINDOW_SECONDS = 300      # 5-minute freshness window (matches T11)
DEFAULT_FUTURE_SKEW_SECONDS = 300  # if T11 allows less future skew, pass it in
TTL_MARGIN_SECONDS = 30

# Reason codes - must match docs/api-contract.md section 2
REASON_VALID = "valid"
REASON_REPLAYED = "replayed"
REASON_STORE_ERROR = "store_unavailable"


@dataclass(frozen=True)
class ReplayResult:
    passed: bool
    reason: str          # "valid" | "replayed" | "store_unavailable"
    http_status: int     # 200 | 409 | 503

    def __bool__(self) -> bool:
        return self.passed


def ttl_for_window(window_seconds: float = DEFAULT_WINDOW_SECONDS,
                   future_skew_seconds: float = DEFAULT_FUTURE_SKEW_SECONDS,
                   margin_seconds: float = TTL_MARGIN_SECONDS) -> float:
    """How long an event_id must be remembered (see module docstring)."""
    return window_seconds + future_skew_seconds + margin_seconds


def check_replay(event_id: str, store: EventStore, *,
                 window_seconds: float = DEFAULT_WINDOW_SECONDS,
                 future_skew_seconds: float = DEFAULT_FUTURE_SKEW_SECONDS,
                 key_id: str | None = None) -> ReplayResult:
    """Return passed=True only if event_id has never been seen (and record it).

    key_id (optional) namespaces the ID so two senders/keys that happen to
    reuse the same event_id do not collide.

    Fails CLOSED: if the store is down we return 503 rather than accept an
    event we could not check.
    """
    if not isinstance(event_id, str) or not event_id.strip():
        # Malformed input is rejected, never crashes the pipeline.
        return ReplayResult(False, REASON_REPLAYED, 409)

    unique = f"{key_id}:{event_id}" if key_id else event_id
    ttl = ttl_for_window(window_seconds, future_skew_seconds)
    try:
        is_new = store.check_and_set(unique, ttl)
    except StoreUnavailable as e:
        log.warning("event store unavailable, failing closed: %s", e)
        return ReplayResult(False, REASON_STORE_ERROR, 503)

    if is_new:
        return ReplayResult(True, REASON_VALID, 200)
    return ReplayResult(False, REASON_REPLAYED, 409)
