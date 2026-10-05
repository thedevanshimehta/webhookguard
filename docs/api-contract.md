# WebhookGuard API Contract

Owner: Devanshi Mehta (T02) | Status: **v1.0, frozen Day 2**. Changes need the Lead's approval and a note to every dependent owner.

All modules code against this document. If it is not written here, ask before assuming.

---

## 1. Webhook request

`POST /webhook` over HTTPS. The body is the **raw JSON payload**. Security metadata travels in headers, so the signed bytes are exactly the bytes received (no JSON re-serialisation problems).

| Header | Example | Rules |
|---|---|---|
| `Content-Type` | `application/json` | Required |
| `X-Webhook-Timestamp` | `1727445520` | Unix time in **seconds**, integer |
| `X-Webhook-Event-Id` | `evt_12345` | Unique per event. Allowed chars `A-Z a-z 0-9 _ -`, length 8-64. **No dots.** Sender generates `evt_` + `uuid4().hex` |
| `X-Webhook-Key-Id` | `k1` | Identifies which secret signed the request (needed for rotation) |
| `X-Webhook-Signature` | `sha256=ab0d1d...` | `sha256=` + lowercase hex HMAC |

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

1. **Parse and validate** headers and body (malformed -> reject)
2. **Look up key** by `X-Webhook-Key-Id` (unknown -> reject)
3. **Signature check** (mismatch -> reject)
4. **Timestamp check** (outside window -> reject)
5. **Replay check** (event_id already seen -> reject)
6. **Accept** and forward to the application

Why this order: the event_id is stored **only after** signature and timestamp pass, so an attacker cannot fill the store with fake IDs, and cheap unauthenticated garbage is rejected before touching the database.

## 4. Responses

| Outcome | `reason` | HTTP |
|---|---|---|
| Accepted | `valid` | 200 |
| Missing/invalid header, bad JSON | `malformed` | 400 |
| Key ID not known | `unknown_key` | 401 |
| Signature mismatch | `invalid_signature` | 401 |
| Timestamp outside window | `expired` | 400 |
| Event ID already processed | `replayed` | 409 |

Response body (always JSON):
```json
{"status":"rejected","reason":"replayed","event_id":"evt_12345"}
```
`status` is `accepted` or `rejected`.

> **Forged vs tampered:** a receiver cannot cryptographically tell these apart (both just fail the HMAC). The contract therefore uses one code, `invalid_signature`. The dashboard shows it as "Forged / Tampered". Attack scripts identify which attack they ran in their own output.

## 5. Timestamp rule
- Window is symmetric: accept if `abs(now - timestamp) <= TIMESTAMP_WINDOW_SECONDS` (default **300**).
- Older than the window = `expired`. Further in the future than the window is also rejected (same code `expired`).
- `now` uses the receiver's clock in UTC seconds. `check_timestamp` takes an optional `now` argument so tests can control time.

## 6. Replay rule
- Store key = `event_id`. Value is only a "seen" marker.
- TTL = `2 * TIMESTAMP_WINDOW_SECONDS + 10` seconds. (Window is symmetric, so a valid request can stay replayable for up to 2x the window.)
- `check_and_set` must be **atomic**: two concurrent requests with the same ID, exactly one gets "new".

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
- `decision`: `accepted` | `rejected`. `reason`: one of the codes in section 4.
- Missing values (e.g. `event_id` on a malformed request) are `null`.
- **Never log** secrets, full signatures, or the raw body.

## 8. Module interfaces (Python 3.10+)

Shared types live in `receiver/pipeline/result.py`.

```python
@dataclass(frozen=True)
class CheckResult:
    ok: bool
    reason: str          # "valid" if ok, else a reason code from section 4

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
| `receiver/crypto/hmac_utils.py` (Laxmi) | `build_canonical(timestamp: str, event_id: str, body: bytes) -> bytes` | Section 2 canonical string |
| | `compute_signature(secret: bytes, canonical: bytes) -> str` | Lowercase hex HMAC-SHA256 |
| | `verify_signature(secret: bytes, canonical: bytes, received_hex: str) -> bool` | Constant-time compare; `received_hex` has the `sha256=` prefix already removed |
| `keys/key_manager.py` (Devanshi) | `get_key(key_id: str) -> bytes \| None` | Secret for a key ID, `None` if unknown/retired |
| | `get_active_keys() -> dict[str, bytes]` | All keys valid for **verification** (new + old during rotation overlap) |
| | `get_signing_key() -> tuple[str, bytes]` | `(key_id, secret)` the sender should sign with |
| `receiver/pipeline/signature_check.py` (Vedansh) | `check_signature(key_id, timestamp, event_id, body, signature_header) -> CheckResult` | Strips `sha256=`, uses `key_manager` + `hmac_utils` |
| `receiver/pipeline/endpoint.py` (Vedansh) | Flask route `POST /webhook` | Extracts headers/body, calls `decision_engine.verify_webhook`, returns JSON from section 4 |
| `receiver/pipeline/timestamp_check.py` (Anushka) | `check_timestamp(timestamp: int, now: int \| None = None, window: int = 300) -> CheckResult` | Section 5 |
| `store/event_store.py` (Yashvi) | `class EventStore: check_and_set(event_id: str, ttl_seconds: int) -> bool` | `True` = first time seen (new), `False` = duplicate. Atomic |
| | `get_event_store(config) -> EventStore` | Returns Redis or SQLite implementation per `EVENT_STORE` |
| `receiver/pipeline/replay_check.py` (Yashvi) | `check_replay(event_id: str, store: EventStore, ttl_seconds: int) -> CheckResult` | Wraps `check_and_set` |
| `receiver/pipeline/decision_engine.py` (Harsh) | `verify_webhook(headers: dict, body: bytes, source_ip: str) -> Decision` | Runs section 3 in order, calls the logger, returns `Decision` |
| `logs-dashboard/logger.py` (Harsh) | `log_decision(decision: Decision, source_ip: str, request_timestamp: int \| None, body: bytes) -> None` | Appends one line per section 7 to `LOG_PATH` |
| `app/config.py` (Devanshi) | `load_config() -> Config` | Fields: `timestamp_window`, `event_store`, `sqlite_path`, `redis_url`, `log_path` |

## 9. Configuration (environment variables, see `.env.example`)

| Variable | Default | Meaning |
|---|---|---|
| `WEBHOOKGUARD_KEYS` | none (required) | `key_id:secret` pairs, comma separated. **First entry is the active signing key**; the rest are accepted for verification only |
| `TIMESTAMP_WINDOW_SECONDS` | `300` | Freshness window |
| `EVENT_STORE` | `sqlite` | `sqlite` or `redis` |
| `SQLITE_PATH` | `./webhookguard.db` | SQLite file |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `LOG_PATH` | `./logs/security.jsonl` | Security log file |

## 10. Stubs while waiting for upstream modules
- **Key manager stub:** read `WEBHOOKGUARD_KEYS` directly from the environment.
- **Event store stub:** a Python `set` guarded by a lock, same `check_and_set` signature.
- Replace the stub as soon as the real module is merged into `dev`.
