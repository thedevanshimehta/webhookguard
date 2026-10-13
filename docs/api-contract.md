# WebhookGuard API Contract

Owner: Devanshi Mehta (T02) | Status: **v1.1** (v1.0 frozen Day 2; v1.1 adds the review fixes listed in section 11). Changes need the Lead's approval and a note to every dependent owner.

All modules code against this document. If it is not written here, ask before assuming.

---

## 1. Webhook request

`POST /webhook` over HTTPS. The body is the **raw JSON payload**. Security metadata travels in headers, so the signed bytes are exactly the bytes received (no JSON re-serialisation problems).

| Header | Example | Rules |
|---|---|---|
| `Content-Type` | `application/json` | Required |
| `X-Webhook-Timestamp` | `1727445520` | Unix time in **seconds**, plain ASCII digits only (no sign, spaces or `_`) |
| `X-Webhook-Event-Id` | `evt_12345` | Unique per event. Allowed chars `A-Z a-z 0-9 _ -`, length 8-64. **No dots.** Sender generates `evt_` + `uuid4().hex` |
| `X-Webhook-Key-Id` | `k1` | Identifies which secret signed the request (needed for rotation) |
| `X-Webhook-Signature` | `sha256=ab0d1d...` | `sha256=` + lowercase hex HMAC |

The body must be a JSON **object** (not a number, string, array or `null`) and at most
`MAX_BODY_BYTES` (default 1 MiB).

Body example:
```json
{"event":"payment.success","amount":500,"currency":"INR"}
```

## 2. Signing rule (sender and receiver must match exactly)

```
canonical  = timestamp + "." + event_id + "." + raw_body_bytes
signature  = HMAC-SHA256(secret, canonical)  -> lowercase hex
header     = "sha256=" + signature
```
- `timestamp` and `event_id` are ASCII strings exactly as sent in the headers.
- `raw_body_bytes` is the unmodified request body. Never parse and re-dump the JSON before verifying.
- Compare with `hmac.compare_digest` only.

**Test vector** (use in unit tests):

| Item | Value |
|---|---|
| secret | `test-secret` |
| timestamp | `1727445520` |
| event_id | `evt_12345` |
| body | `{"event":"payment.success","amount":500,"currency":"INR"}` |
| canonical | `1727445520.evt_12345.{"event":"payment.success","amount":500,"currency":"INR"}` |
| signature | `ab0d1dd6b5aa74d4b082edd7a61a2d42e09e36173303fcccf2657f47a3265f2a` |
| body SHA-256 | `d1119b9d8c5f9a6142572e7eecdc4f05e88764c4e4481c9b35f0cd78992841f9` |

## 3. Verification order (the decision engine must follow this)

1. **Parse and validate** headers and body (malformed -> reject; too large -> reject before reading)
2. **Look up key** by `X-Webhook-Key-Id` (unknown -> reject)
3. **Signature check** (mismatch -> reject)
4. **Timestamp check** (outside window -> reject)
5. **Replay check** (event_id already seen -> reject)
6. **Accept** and forward to the application. If the application raises, the event ID is
   released from the store (so the sender's retry is accepted) and the response is `processing_failed`.

Why this order: the event_id is stored **only after** signature and timestamp pass, so an attacker cannot fill the store with fake IDs, and cheap unauthenticated garbage is rejected before touching the database.

## 4. Responses

| Outcome | `reason` | HTTP |
|---|---|---|
| Accepted | `valid` | 200 |
| Missing/invalid header, bad JSON | `malformed` | 400 |
| Key ID not known | `invalid_signature` (logged as `unknown_key`) | 401 |
| Signature mismatch | `invalid_signature` | 401 |
| Timestamp outside window | `expired` | 400 |
| Event ID already processed | `replayed` | 409 |
| Event store unavailable | `store_unavailable` | 503 |
| Body larger than `MAX_BODY_BYTES` | `too_large` | 413 |
| Accepted, but the application failed to process it | `processing_failed` | 500 |

Response body (always JSON):
```json
{"status":"rejected","reason":"replayed","event_id":"evt_12345"}
```
`status` is `accepted` or `rejected`.

> **Unknown key:** the response does not reveal whether a key ID exists (that would let anyone
> probe for valid IDs), so it is the same as for a bad signature. The security log keeps the precise
> reason `unknown_key` for troubleshooting.

> **Forged vs tampered:** a receiver cannot cryptographically tell these apart (both just fail the HMAC). The contract therefore uses one code, `invalid_signature`. The dashboard shows it as "Forged / Tampered". Attack scripts identify which attack they ran in their own output.

## 5. Timestamp rule
- Window is symmetric: accept if `abs(now - timestamp) <= TIMESTAMP_WINDOW_SECONDS` (default **300**).
- Older than the window = `expired`. Further in the future than the window is also rejected (same code `expired`).
- `now` uses the receiver's clock in UTC seconds. `check_timestamp` takes an optional `now` argument so tests can control time.

## 6. Replay rule

- The event store exposes `check_and_set(event_id, ttl_seconds) -> bool`. It returns `True` when the event is new and `False` when the event has already been seen.
- The operation must be **atomic**: two concurrent requests with the same store key must not both be accepted as new.
- When a key ID is available, the receiver namespaces the store key as `key_id:event_id` to avoid collisions between events signed under different keys.
- The replay TTL is `2 * TIMESTAMP_WINDOW_SECONDS + 30` seconds under the current implementation. The additional 30 seconds provides a small safety margin.
- The receiver records an event only after signature and timestamp validation pass.
- `EventStore.release(event_id)` forgets an event. The endpoint calls it (through
  `release_replay`) when the application fails to process an accepted event, so the event is
  not lost when the sender retries.
- If the event store is unavailable, reject the request with reason `store_unavailable` and HTTP 503. Do not bypass replay protection.
- Supported implementations: SQLite, Redis, and in-memory storage. In-memory storage is intended for development and testing; it does not provide shared replay protection across processes or survive restarts.

## 7. Security log entry (JSON Lines, one object per line)

```json
{
  "logged_at": "2026-10-05T10:15:30Z",
  "event_id": "evt_12345",
  "key_id": "k1",
  "decision": "rejected",
  "reason": "replayed",
  "source_ip": "203.0.113.5",
  "request_timestamp": 1727445520,
  "body_sha256": "d1119b9d..."
}
```
- `decision`: `accepted` | `rejected`. `reason`: one of the codes in section 4, or `unknown_key`.
- A request rejected as `too_large` has `body_sha256: null` (the body is never read).
- Missing values (e.g. `event_id` on a malformed request) are `null`.
- **Never log** secrets, full signatures, or the raw body.

## 8. Module interfaces (Python 3.10+)

Shared types live in `receiver/pipeline/result.py`.

```python
@dataclass(frozen=True)
class CheckResult:
    ok: bool
    reason: str

@dataclass(frozen=True)
class Decision:
    accepted: bool
    reason: str
    http_status: int
    event_id: str | None
    key_id: str | None
```

| Module (owner) | Function | Behaviour |
|---|---|---|
| `receiver/crypto/hmac_utils.py` (Laxmi) | `build_canonical(timestamp: str, event_id: str, body: bytes) -> bytes` | Builds the canonical signing bytes according to Section 2 |
| | `compute_signature(secret: bytes, canonical: bytes) -> str` | Returns lowercase hexadecimal HMAC-SHA256 |
| | `verify_signature(secret: bytes, canonical: bytes, received_hex: str) -> bool` | Constant-time comparison; `received_hex` has the `sha256=` prefix removed |
| `keys/key_manager.py` (Devanshi) | `get_key(key_id: str) -> bytes | None` | Returns the secret for a key ID, or `None` if unknown |
| | `get_active_keys() -> dict[str, bytes]` | Returns keys accepted for verification during rotation overlap |
| | `get_signing_key() -> tuple[str, bytes]` | Returns the active signing key ID and secret |
| `receiver/pipeline/signature_check.py` (Vedansh) | `check_signature(key_id, timestamp, event_id, body, signature_header) -> CheckResult` | Checks the key and HMAC signature |
| `receiver/pipeline/timestamp_check.py` (Anushka) | `check_timestamp(timestamp: int, now: int | None = None, window: int = 300) -> CheckResult` | Validates the timestamp freshness window |
| `store/event_store.py` (Yashvi) | `EventStore.check_and_set(event_id: str, ttl_seconds: int) -> bool` | Atomically records an event; `True` means new, `False` means duplicate |
| | `EventStore.release(event_id: str) -> None` | Forgets an event so a retry is accepted |
| | `EventStore.purge_expired() -> int` | Removes expired entries where supported |
| | `EventStore.close() -> None` | Releases store resources |
| | `create_event_store(kind="sqlite", *, path="data/events.db", redis_url="redis://localhost:6379/0", clock=None) -> EventStore` | Creates the selected SQLite, Redis, or in-memory implementation |
| | `StoreUnavailable` | Indicates that a store operation could not be completed |
| `receiver/pipeline/replay_check.py` (Yashvi) | `check_replay(event_id, store, *, window_seconds=300, future_skew_seconds=300, key_id=None) -> ReplayResult` | Wraps the atomic store operation and reports valid, replayed, store-unavailable or malformed outcomes. `ReplayResult.ok` is the same as `.passed` |
| | `release_replay(event_id, store, *, key_id=None) -> bool` | Releases an event recorded by `check_replay` |
| `receiver/pipeline/decision_engine.py` (Harsh) | `verify_webhook(headers, body, source_ip, event_store=None, config=None) -> Decision` | Runs verification with the supplied store and config, logs the decision, and returns a `Decision`. Header names are case-insensitive. Without a store, one shared default store per config is used |
| `logs-dashboard/logger.py` (Harsh) | `log_decision(decision: Decision, source_ip: str, request_timestamp: int | None, body: bytes | None, log_path: str | None = None) -> None` | Appends a security log entry as defined in Section 7; reads `LOG_PATH` only if `log_path` is omitted |
| | `read_log(log_path: str, limit: int | None = None) -> list[dict]` | Reads entries for the dashboard |
| `receiver/pipeline/security_log.py` | `log_decision`, `read_log` | Single import point for the logger (its folder name has a hyphen) |
| `app/config.py` (Devanshi) | `load_config() -> Config` | Provides `timestamp_window`, `event_store`, `event_store_path`, `redis_url`, `log_path` and `max_body_bytes`; `sqlite_path` is a compatibility property |
| | `load_env() -> None` | Loads the project `.env`; called by every entry point (receiver, sender CLI, attack scripts) |
| `receiver/pipeline/endpoint.py` (Vedansh) | `create_webhook_app(verifier=None, handler=None, dashboard=True)` | Creates the Flask app. Unless a custom verifier is supplied, loads config and creates one event store at startup and shares both with every request, applies `MAX_BODY_BYTES`, and serves `/dashboard`. `handler(payload, decision)` is called for each accepted event |
| `app/main.py` (Devanshi) | `python -m app.main`, `create_app()` | Entrypoint: protected receiver with the demo payment ledger (`/ledger`, `/reset`) |

## 9. Configuration

Environment variables are documented in `.env.example`.

| Variable | Default | Meaning |
|---|---|---|
| `WEBHOOKGUARD_KEYS` | None (required for signature verification) | Comma-separated `key_id:secret` pairs. The `.env.example` placeholder is refused. The first entry is the active signing key; all configured keys are accepted for verification during rotation overlap. |
| `TIMESTAMP_WINDOW_SECONDS` | `300` | Symmetric timestamp freshness window, in seconds |
| `EVENT_STORE` | `sqlite` | Backend selection: `sqlite`, `redis`, or `memory` |
| `EVENT_STORE_PATH` | `data/events.db` | SQLite database path; used when `EVENT_STORE=sqlite` |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL; used when `EVENT_STORE=redis` |
| `LOG_PATH` | `logs/security.jsonl` | JSON Lines security-log path |
| `MAX_BODY_BYTES` | `1048576` | Largest accepted body; larger requests get `413 too_large` |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Where `python -m app.main` listens |

**Compatibility:** `SQLITE_PATH` is accepted as a legacy fallback for `EVENT_STORE_PATH`. If both are set, `EVENT_STORE_PATH` takes precedence.

**Lifecycle:** The Flask application creates the selected event store once during app creation and shares that instance with the verification pipeline. Store failures produce `store_unavailable` / HTTP 503 rather than silently accepting a request.



## 10. Stubs while waiting for upstream modules
- **Key manager stub:** read `WEBHOOKGUARD_KEYS` directly from the environment.
- **Event store stub:** a Python `set` guarded by a lock, same `check_and_set` signature.
- Replace the stub as soon as the real module is merged into `dev`.

## 11. Changelog

**v1.1** (review fixes):
- Timestamp header must be plain ASCII digits; body must be a JSON object.
- New reasons `too_large` (413) and `processing_failed` (500).
- `unknown_key` is no longer sent to the client (it is sent as `invalid_signature`); it is still logged.
- `EventStore.release` / `release_replay`: a failed event is released so its retry is accepted.
- `check_replay` reports an empty event ID as `malformed` (400), not `replayed`.
- `verify_webhook` and `log_decision` take the startup config / log path instead of reloading config per request.
- `WEBHOOKGUARD_KEYS` refuses the `.env.example` placeholder secret.
- New settings `MAX_BODY_BYTES`, `HOST`, `PORT`; new entrypoint `app/main.py`; dashboard at `/dashboard`.
