"""Timestamp validation (T11).

Step 4 of the verification order in docs/api-contract.md (section 3).

Rule (contract section 5): the window is symmetric. A request is accepted
when abs(now - timestamp) <= window. Requests older than the window and
requests further in the future than the window are both rejected with the
same reason code, "expired".
"""

import time

from receiver.pipeline.result import EXPIRED, MALFORMED, VALID, CheckResult

DEFAULT_WINDOW_SECONDS = 300


def check_timestamp(
    timestamp: int,
    now: int | None = None,
    window: int = DEFAULT_WINDOW_SECONDS,
) -> CheckResult:
    """Check that ``timestamp`` (Unix seconds, UTC) is inside the freshness window.

    Args:
        timestamp: Value of the X-Webhook-Timestamp header, already parsed to int.
        now: Current Unix time in seconds. Defaults to the receiver's clock.
            Tests pass this in to control time.
        window: Allowed difference in seconds (TIMESTAMP_WINDOW_SECONDS).

    Returns:
        CheckResult(ok=True, reason=VALID) when inside the window,
        CheckResult(ok=False, reason=EXPIRED) when outside it,
        CheckResult(ok=False, reason=MALFORMED) if ``timestamp`` is not an int.
    """
    # bool is a subclass of int in Python, so exclude it explicitly.
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        return CheckResult(ok=False, reason=MALFORMED)

    if now is None:
        now = int(time.time())

    if abs(now - timestamp) <= window:
        return CheckResult(ok=True, reason=VALID)

    return CheckResult(ok=False, reason=EXPIRED)
