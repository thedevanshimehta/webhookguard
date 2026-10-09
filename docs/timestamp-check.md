# Timestamp Check (T11, Anushka Gupte)

Step 4 of the verification order (`docs/api-contract.md`, section 3). It rejects
requests whose `X-Webhook-Timestamp` is too old (expired) or too far in the future,
so a captured valid request cannot be reused later.

## Interface

```python
# receiver/pipeline/timestamp_check.py
check_timestamp(timestamp: int, now: int | None = None, window: int = 300) -> CheckResult
```

`CheckResult` and the reason-code constants (`VALID`, `EXPIRED`, `MALFORMED`) come from
`receiver/pipeline/result.py`.

| Input | Result | Reason | HTTP |
|---|---|---|---|
| `abs(now - timestamp) <= window` | `ok=True` | `valid` | 200 |
| older than the window | `ok=False` | `expired` | 400 |
| further in the future than the window | `ok=False` | `expired` | 400 |
| `timestamp` is not an `int` (str, None, float, bool) | `ok=False` | `malformed` | 400 |

## For the decision engine (T14, Harsh)

- Call it **after** the signature check and **before** the replay check (contract section 3).
- Pass an already-parsed `int`. Converting the header string to `int` (and returning
  `malformed` if that fails) is the caller's job. The `malformed` result here is only a safety net.
- Pass `window=config.timestamp_window` (from `TIMESTAMP_WINDOW_SECONDS`, default 300).
  The function has no config dependency of its own.

## Design notes

- **Symmetric window**: the same `window` applies to past and future timestamps, so the
  allowed future skew equals the window. T13 must use the same value for its TTL calculation.
- **Boundary is inclusive**: exactly `window` seconds away is accepted, `window + 1` is rejected.
- **Clock**: `now` defaults to `int(time.time())` (UTC seconds). Tests pass `now` to control time.
- **No state, no I/O**: pure function, safe to call from any thread.
- **Booleans are rejected**: `True` is an `int` in Python, so it is excluded explicitly.

## Config

| Variable | Default | Meaning |
|---|---|---|
| `TIMESTAMP_WINDOW_SECONDS` | `300` | Freshness window, read by `app/config.py` and passed in by the caller |

## Test

    pip install -r requirements.txt
    python -m pytest tests/test_timestamp_check.py -v
