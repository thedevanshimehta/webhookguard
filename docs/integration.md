# End-to-End Integration (T05, Devanshi Mehta)

Checks that every module works together as one system, not just on its own. Unit tests
prove each piece; this suite proves the pieces are wired in the order the contract requires
and that the four attacks are stopped by the running receiver.

## What is exercised

No test doubles. Each test uses the real modules:

```
sender.create_signed_webhook / attacks.common.make_request
   -> Flask app (receiver/pipeline/endpoint.py, create_webhook_app)
   -> decision engine (verify_webhook)
        -> key manager (WEBHOOKGUARD_KEYS)
        -> HMAC signature check
        -> timestamp check
        -> replay check -> SQLite event store
   -> security logger (JSON Lines)
```

Requests go through Flask's test client, so no port is opened. Every test gets its own
key, SQLite database and log file in pytest's `tmp_path`, so nothing touches `data/` or `logs/`.

## Scenarios

| Area | Scenario | Expected |
|---|---|---|
| Control | Event built by the real sender | `200 valid` |
| Control | 20 different events in a row | all `200` |
| Forgery | Signed with a wrong secret | `401 invalid_signature` |
| Tampering | Amount changed 500 -> 5000, old signature kept | `401 invalid_signature` |
| Tampering | Timestamp or event ID header changed after signing | `401 invalid_signature` |
| Replay | Same request sent three times | `200`, then `409 replayed` twice |
| Replay | Same event ID re-signed with a new body | `409 replayed` |
| Expiry | Timestamp older than the window | `400 expired` |
| Expiry | Timestamp further in the future than the window | `400 expired` |
| Ordering | Tampered and expired copies sent first | event ID not consumed; genuine request still `200` |
| Keys | Unknown key ID | `401 invalid_signature` to the client, `unknown_key` in the log |
| Keys | Rotation: `k2` signs, `k1` still accepted during overlap, `k1` rejected after retirement | `200`, `200`, `401` (logged `unknown_key`) |
| Malformed | Each security header missing; wrong Content-Type; invalid JSON | `400 malformed` |
| Persistence | Receiver restarted with the same SQLite file, then replayed | `409 replayed` |
| Concurrency | 16 threads deliver the same request at once | exactly one `200`, fifteen `409` |
| Logging | One log line per decision, correct `reason`, `decision`, `key_id`, `body_sha256` | as listed |
| Logging | Log contains no secret, no signature and no raw body | none found |

## Review fixes

`tests/test_review_fixes.py` adds one or more regression tests for each issue found in the
dev-branch review:
- configuration is loaded once per app, not per request;
- non-object JSON and non-canonical timestamps are `malformed`;
- the logger keeps a unique module name;
- a direct `verify_webhook` call keeps replay state;
- placeholder secrets are refused;
- the sender CLI and attack scripts read `.env`;
- bodies over `MAX_BODY_BYTES` get a JSON `413 too_large`;
- an empty event ID is `malformed`;
- a failed application call is released so the retry succeeds (memory, SQLite and Redis);
- the protected ledger holds only genuine payments;
- the dashboard serves its page and data and never inserts log values as HTML.

## Run

    pip install -r requirements.txt
    python -m pytest tests/test_end_to_end.py tests/test_review_fixes.py -v

The suite sets its own environment variables, so it does not need a `.env` file.

## Live demo against a running receiver

The in-process suite above is the automated check. For the live demo with two receivers
and the attack scripts, follow `app/demo.md`.
