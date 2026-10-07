"""Timestamp / freshness validation (task T11, owner: Anushka Gupte).

Rules from docs/api-contract.md section 5:
  * Window is symmetric: accept if abs(now - timestamp) <= window (default 300s).
  * Older than the window -> reason "expired". Further in the future than the
    window is ALSO rejected with the same code "expired".
  * `now` uses the receiver's clock in UTC seconds; the optional `now`
    argument lets tests control time.
"""
from __future__ import annotations

import time

from receiver.pipeline.result import CheckResult, EXPIRED, VALID

DEFAULT_WINDOW_SECONDS = 300  # 5 minutes, per contract section 5


def check_timestamp(timestamp: int, now: int | None = None,
                    window: int = DEFAULT_WINDOW_SECONDS) -> CheckResult:
    """Accept iff |now - timestamp| <= window. Rejects as 'expired' otherwise."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return CheckResult(False, EXPIRED)

    if ts < 0 or window <= 0:
        return CheckResult(False, EXPIRED)

    current = time.time() if now is None else now
    if abs(current - ts) <= window:
        return CheckResult(True, VALID)
    return CheckResult(False, EXPIRED)
