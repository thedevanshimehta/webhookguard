# WebhookGuard: Final Report

**Team:** Not Today, Hackers! | Applied Cryptography and Network Security Design Challenge (ACNS-DC) 2026-27
**Course:** Cryptography and Network Security (CE305/CS305), Sardar Patel Institute of Technology, Mumbai
**Report owner:** Devanshi Mehta (T06) | **Branch:** `dev`

| Roll no. | Member | Roll no. | Member |
|---|---|---|---|
| 2024300136 | Devanshi Mehta (Lead) | 2024300066 | Harsh Ghole |
| 2024300010 | Suhana Asrani | 2024300145 | Laksh Nagrare |
| 2024300009 | Laxmi Angadi | 2024300040 | Sampada Daware |
| 2024300065 | Vedansh Gholba | 2024300146 | Gurshaan Nandrajog |
| 2024300074 | Anushka Gupte | 2024300031 | Yashvi Dalal |

---

## 1. Abstract

Webhooks are server-to-server HTTP callbacks that trigger real actions, such as marking an
order as paid, with no human in the loop. A receiver that trusts them blindly can be fooled
by a **forged** event, a **tampered** event, a **replayed** event or an **expired** event.

WebhookGuard is a receiver-side verification layer that runs before the application acts
on any webhook. It authenticates the sender and protects integrity with **HMAC-SHA256**
computed over `timestamp.event_id.raw_body`. It enforces freshness with a **symmetric
±300 s timestamp window**, and it prevents duplicates with an **atomic event-ID store**
(SQLite or Redis) whose entries expire once the timestamp check would reject the request
anyway.

In a live demonstration, all four attacks succeeded against a deliberately vulnerable
receiver, which made 5 payouts totalling INR 7000 without the attacker ever knowing the
secret. All four were rejected by WebhookGuard, whose application ledger recorded only the
genuine INR 500. The automated suite has 165 passing tests, covering all three store backends.

## 2. Problem

### 2.1 Threats

| Threat | Example | Property violated |
|---|---|---|
| Forgery | Attacker sends a fake `payment.success` | Authenticity |
| Tampering | Amount changed from INR 500 to INR 5000 in transit | Integrity |
| Replay | A captured valid request is sent again | Uniqueness |
| Expired request | A request captured earlier is reused much later | Freshness |

### 2.2 Why a signature alone is not enough

A valid HMAC stays valid forever for the bytes it covers. Signing only the body stops
forgery and tampering, but a captured request can be replayed indefinitely. WebhookGuard
therefore binds the **timestamp** and the **event ID** into the signed message. Neither
can be changed without breaking the signature, so freshness and uniqueness can be enforced
on values the attacker cannot alter.

### 2.3 Attacker model

The attacker can observe, capture, modify and resend HTTP requests to the receiver, and can
send arbitrary requests of their own. The attacker does **not** know the shared secret.
Compromise of the sender or of the secret itself is out of scope (see section 8).

## 3. Design

### 3.1 Wire format (`docs/api-contract.md`)

Security metadata travels in headers, so the bytes that are verified are exactly the bytes
received. The JSON body is never re-serialised before verification.

| Header | Example |
|---|---|
| `Content-Type` | `application/json` |
| `X-Webhook-Timestamp` | `1727445520` (Unix seconds, ASCII digits only) |
| `X-Webhook-Event-Id` | `evt_` + 32 hex chars (allowed `A-Z a-z 0-9 _ -`, 8-64 chars, no dots) |
| `X-Webhook-Key-Id` | `k1` |
| `X-Webhook-Signature` | `sha256=` + 64 lowercase hex chars |

The body must be a JSON object of at most `MAX_BODY_BYTES` (default 1 MiB).

### 3.2 Signing rule

```
canonical = timestamp + "." + event_id + "." + raw_body_bytes
signature = HEX( HMAC-SHA256(secret, canonical) )
```

Because neither `timestamp` nor `event_id` can contain a `.`, the canonical string splits
into its three fields in only one way. A boundary-shifting attack (moving bytes from one
field into another while keeping the same concatenation) is therefore impossible. The
contract publishes a fixed test vector, which both sender and receiver tests check.

### 3.3 Verification order

```
POST /webhook
  0. Body over MAX_BODY_BYTES      -> 413 too_large  (body never read)
  1. Parse headers + body          -> 400 malformed
  2. Look up key by Key-Id         -> 401 invalid_signature  (logged as unknown_key)
  3. HMAC check (constant time)    -> 401 invalid_signature
  4. Timestamp |now - ts| <= 300   -> 400 expired
  5. Atomic check_and_set(event)   -> 409 replayed   (503 store_unavailable)
  6. Forward to the application    -> 200 valid
     application raised            -> 500 processing_failed, event ID released for the retry
  Every outcome -> one JSON line in the security log
```

The order matters for security, not just speed. The replay check *writes* to the store, so
it runs last. Only requests that are authentic and fresh can record an event ID. If it ran
earlier, an attacker without the key could send junk with guessed IDs and "burn" them, and
the genuine event with that ID would later be rejected as a replay.

### 3.4 Why timestamp and event ID are both needed

| Mechanism alone | Weakness |
|---|---|
| Timestamp window only | Replay is still possible *within* the 300 s window |
| Event-ID store only | Store must remember every ID forever; grows without bound |
| **Both together** | Event IDs only need to be remembered while the timestamp check could still pass. Storage stays bounded and in-window replays are caught. |

Replay TTL = window + allowed future skew + 30 s margin = **630 s** with defaults. A
request stamped 300 s in the future remains timestamp-valid until 600 s from now, so a
TTL equal to the window alone would leave a gap.

### 3.5 Forged vs tampered

Both attacks fail in the same way: the HMAC does not match. A receiver cannot
cryptographically tell them apart, so the contract uses one reason code,
`invalid_signature`, and the dashboard groups them as "Forged / Tampered". The attack
scripts report which attack they ran in their own output.

## 4. Implementation

Python 3.10+, Flask, `hmac`/`hashlib` from the standard library, SQLite (default) or Redis.

| Module | Owner | Responsibility |
|---|---|---|
| `docs/api-contract.md` | Devanshi Mehta (T01-T02) | Interface (v1.1), signing rule, test vector, reason codes |
| `keys/key_manager.py` | Devanshi Mehta (T03) | Keys from `WEBHOOKGUARD_KEYS`, rotation with overlap |
| `app/config.py`, `app/main.py`, `app/ledger.py` | Devanshi Mehta (T04) | Validated configuration from `.env`; entrypoint; demo payments application |
| `receiver/crypto/hmac_utils.py` | Laxmi Angadi (T07) | Canonical bytes, HMAC-SHA256, constant-time compare |
| `tests/test_integration.py` | Laxmi Angadi (T08) | Crypto + replay integration tests |
| `sender/sender.py`, `sender/cli.py` | Suhana Asrani (T09) | Signs and sends events; CLI for demos |
| `receiver/pipeline/endpoint.py`, `signature_check.py` | Vedansh Gholba (T10) | `POST /webhook`, key lookup, signature check |
| `receiver/pipeline/timestamp_check.py` | Anushka Gupte (T11) | Symmetric freshness window |
| `app/vulnerable_receiver.py`, `app/demo.md` | Anushka Gupte (T12) | Unprotected receiver for comparison |
| `store/event_store.py`, `receiver/pipeline/replay_check.py` | Yashvi Dalal (T13) | Atomic event store (SQLite / Redis / memory), replay check |
| `receiver/pipeline/decision_engine.py`, `logs-dashboard/logger.py`, `receiver/pipeline/security_log.py` | Harsh Ghole (T14) | Orchestrates checks, writes security log |
| `attacks/forge.py`, `attacks/tamper.py` | Laksh Nagrare (T15) | Forgery and tampering demonstrations |
| `attacks/replay.py`, `attacks/expired.py`, `docs/attack-results.md` | Gurshaan Nandrajog (T16-T17) | Replay and expiry demonstrations |
| `logs-dashboard/dashboard.html` | Sampada Daware (T18) | Security dashboard served at `/dashboard` |
| `tests/test_end_to_end.py`, `tests/test_review_fixes.py`, `docs/integration.md`, this report | Devanshi Mehta (T05-T06) | End-to-end integration, review regression tests, final report |

### 4.1 Key highlights

- **Constant-time comparison.** `hmac.compare_digest` is used after strict format checks
  on the received hex, so timing does not leak how many characters matched.
- **Atomic replay check.** Redis uses `SET key 1 NX PX ttl`. SQLite uses one statement,
  `INSERT ... ON CONFLICT(event_id) DO UPDATE ... WHERE expires_at <= now`, and treats
  `rowcount == 1` as "new". A separate "check, then insert" would let two concurrent
  copies both pass.
- **Fails closed.** If the store is unreachable, the request is rejected with
  `503 store_unavailable` and is never accepted unchecked.
- **Persistent.** With SQLite or Redis, a receiver restart does not reopen the replay window.
- **Key rotation without downtime.** `WEBHOOKGUARD_KEYS="k2:<new>,k1:<old>"`. The first
  key signs and every listed key verifies. Removing `k1` retires it, and its signatures
  are then rejected (logged as `unknown_key`; the client only sees `invalid_signature`,
  so key IDs cannot be probed).
- **No lost events.** Accepted events are forwarded to the application. If it fails, the
  event ID is released from the store and `500 processing_failed` tells the sender to retry,
  so a legitimate retry is not mistaken for a replay.
- **Bounded input.** Bodies over `MAX_BODY_BYTES` are refused with `413` before being read.
  Timestamps must be plain digits and bodies must be JSON objects.
- **Safe defaults.** The receiver refuses to start with the `.env.example` placeholder secret
  and listens on loopback unless `HOST` is set.
- **Namespaced event IDs.** The store key is `key_id:event_id`, so two senders cannot
  collide on the same ID.
- **Privacy-preserving log.** Each decision is one JSON line containing time, event ID,
  key ID, decision, reason, source IP, request timestamp and the SHA-256 of the body.
  Secrets, signatures and raw bodies are never logged.

## 5. Testing

### 5.1 Automated tests

`python -m pytest tests/ -v`: **165 passed, 0 skipped** (Python 3.14, Flask 3.1, with the
optional `fakeredis` installed so the Redis backend is tested too). The suite was run
repeatedly with identical results.

| File | Tests | Covers |
|---|---:|---|
| `test_review_fixes.py` | 38 | One or more regression tests per issue fixed in the review (section 8.1) |
| `test_end_to_end.py` | 23 | Full stack: sender -> endpoint -> all checks -> SQLite -> log (T05) |
| `test_replay.py` | 27 | Event store backends, TTL, atomicity under 32 threads, fail-closed |
| `test_timestamp_check.py` | 19 | Window boundaries (inclusive), past/future, type checks |
| `test_keys.py` | 16 | Parsing, validation, rotation, no secrets in errors |
| `test_vulnerable_receiver.py` | 11 | Vulnerable receiver accepts every attack; loopback only |
| `test_integration.py` | 8 | Contract test vector, signed-field changes, replay |
| `test_sender.py` | 7 | Unique IDs, exact body bytes, headers, transport errors |
| `test_config.py` | 6 | Configuration validation |
| `test_signature_check.py` | 4 | Valid, tampered, unknown key, header format |
| `test_pipeline_endpoint.py` | 4 | App-level replay, store created once, 503 on store failure |
| `test_endpoint.py` | 1 | Raw body and headers reach the verifier unchanged |
| `test_smoke.py` | 1 | All packages import |

`tests/stress_replay.py` is a separate load script that pushes 100,000 events with 15%
duplicates through the replay check from many threads, and verifies that exactly the
duplicates are rejected.

### 5.2 End-to-end integration (T05)

`tests/test_end_to_end.py` uses no test doubles. Beyond the four attacks it verifies:
- tampered or expired copies do not consume the genuine event's ID;
- an event ID re-signed with a different body is still a replay;
- the full key-rotation lifecycle (overlap, then retirement);
- every malformed-input path;
- replay protection survives a receiver restart;
- 16 simultaneous deliveries of the same request produce exactly one `200`;
- the log has exactly one correct line per decision and no secret, signature or raw body.

Details: `docs/integration.md`.

### 5.3 Live demonstration: vulnerable vs protected

Both receivers were run on the same machine: `python -m app.main` (protected, port 5000) and
`python -m app.vulnerable_receiver` (port 5001). The key was set only in `.env`. The sender
CLI and the four attack scripts were pointed at each in turn (procedure: `app/demo.md`).
Observed results:

| Attack | Vulnerable receiver (:5001) | WebhookGuard (:5000) | Stopped by |
|---|---|---|---|
| Control: genuine event | 200 accepted | 200 `valid` | (n/a) |
| Forgery | 200 accepted | **401 `invalid_signature`** | HMAC |
| Tampering (500 -> 5000) | 200 accepted | **401 `invalid_signature`** | HMAC |
| Replay | 200, 200 (paid twice) | 200, then **409 `replayed`** | Event store |
| Expired (360 s old) | 200 accepted | **400 `expired`** | Timestamp window |

After the four attacks (ledgers reset after the control event):
- the vulnerable receiver's ledger showed **5 payouts totalling INR 7000**, all obtained
  without the secret;
- WebhookGuard's ledger showed **1 payout of INR 500**, the replay script's genuine first
  delivery.

WebhookGuard's security log and dashboard recorded:
`valid, invalid_signature, invalid_signature, valid, replayed, expired`.

## 6. Security analysis

| Requirement | How it is met | Residual risk |
|---|---|---|
| Authenticity | HMAC-SHA256 with a 256-bit random secret; forging requires the key | Secret leakage (mitigated by rotation) |
| Integrity | Signature covers timestamp, event ID and the exact body bytes | None within the model |
| Freshness | Symmetric 300 s window on a signed timestamp | Depends on sender/receiver clocks being within the window |
| Uniqueness | Atomic, persistent, TTL-bounded event-ID store, written only after authentication | In-memory backend loses state on restart (dev/test only) |
| Availability of checks | Store failure -> 503, never silent acceptance | Store outage blocks legitimate traffic (fail-closed by design) |
| Observability | One log line per decision with a specific reason; live dashboard | Dashboard shares the webhook port (loopback by default) |
| Confidentiality | Not provided by HMAC; relies on HTTPS in deployment | Demo runs over plain HTTP on loopback |

## 7. Comparison with existing approaches

| Approach | Forgery | Tampering | Replay | Expiry |
|---|---|---|---|---|
| Secret URL / IP allow-list | partial | no | no | no |
| HMAC over body only (e.g. GitHub `X-Hub-Signature-256`) | yes | yes | no | no |
| HMAC over timestamp + body (e.g. Stripe) | yes | yes | no (within the window) | yes |
| **WebhookGuard: HMAC over timestamp + event ID + body, plus event store** | yes | yes | **yes, also inside window** | yes |

The design matches the industry *Standard Webhooks* scheme (signed `id.timestamp.body`)
and adds an atomic, fail-closed replay store, key IDs for rotation, and per-reason logging.

## 8. Limitations and future work

### 8.1 Issues found in review and fixed

A review of the `dev` branch found the issues below. All are fixed and covered by
`tests/test_review_fixes.py` (and `tests/test_end_to_end.py`).

| # | Issue | Fix |
|---|---|---|
| 1 | Configuration and `.env` re-read on every request (twice) | Loaded once at startup; passed to the decision engine and logger |
| 2 | Any JSON accepted as a body (`123`, `[]`) | Body must be a JSON object, else `malformed` |
| 3 | `int()` accepted timestamps like `1_791_893_091` or `+…`; a 5000-digit timestamp crashed it (500) | ASCII digits only, at most 15, else `malformed` |
| 19 | Deeply nested JSON crashed the parser (500) before the signature check | Treated as `malformed` (400) |
| 4 | Logger loaded under the global module name `logger` | Loaded once under a unique name via `receiver/pipeline/security_log.py` |
| 5 | Unused imports in the decision engine | Removed |
| 6 | `app/main.py` missing; documented start command failed | Added, with a demo payments ledger, `/ledger`, `/reset`, fail-fast key check |
| 7 | `verify_webhook()` without a store created a new store per call | One shared default store per configuration |
| 8 | `.env.example` placeholder secret was accepted | Placeholder secrets are refused; receiver will not start |
| 10 | Sender CLI and attack scripts ignored `.env` | `app.config.load_env()` called by every entry point |
| 11 | No request size limit (20 MB accepted) | `MAX_BODY_BYTES` (1 MiB default) -> JSON `413 too_large`, logged |
| 12 | Empty event ID reported as `replayed` | Reported as `malformed` (400) |
| 13-15 | Stale module docs and attack-results status | Updated with observed results |
| 16 | Dashboard missing | `logs-dashboard/dashboard.html`, served at `/dashboard` |
| 17 | Event marked "seen" before processing; retries after a failure were lost; nothing forwarded to an application | Accepted events go to an application handler; on failure the event is released and `500 processing_failed` is returned |
| 18 | `unknown_key` response revealed which key IDs exist | Client sees `invalid_signature`; the log keeps `unknown_key` |

Issue 9 was a process issue (a commit pushed directly to `dev`, changing the frozen
contract) and is addressed by following CONTRIBUTING.md; the contract is now versioned (v1.1)
with a changelog.

### 8.2 Remaining limitations

1. **Symmetric keys.** HMAC gives no non-repudiation: the receiver could also produce valid
   signatures. Asymmetric signatures (Ed25519) would fix this for multi-receiver setups.
2. **Transport and server.** HTTPS must be enforced in deployment, and the Flask development
   server should be replaced by a production WSGI server. The demo uses loopback HTTP only.
3. **Clock dependence.** Sender and receiver clocks must agree within the 300 s window.
4. **Duplicate deliveries after success** are answered `409 replayed`. A sender that treats
   any non-2xx as failure would keep retrying; answering known, processed IDs with 200 is an
   option for production.
5. **In-memory store** (demo option) loses state on restart; use SQLite or Redis otherwise.
6. **Dashboard access.** The dashboard has no login and shares the webhook port. It listens
   on loopback by default and must not be exposed publicly as is.

Future work: the items above, and an optional anomaly-detection layer over the security log
(for example bursts of `invalid_signature` from one source, as proposed in the design document).

## 9. Conclusion

Each of the four threats maps to one primitive, and each primitive is enforced at a fixed
point in the pipeline:
- forgery and tampering are stopped by HMAC over the exact bytes;
- expiry is stopped by a signed timestamp;
- replay is stopped by an atomic event-ID store that is only written after the request is
  authenticated.

The live comparison shows the impact directly: INR 7000 paid out by the unprotected
receiver, only the genuine INR 500 by WebhookGuard. 165 automated tests back the result,
including a full end-to-end suite and a regression test for every issue found in review.
The remaining limitations are deployment concerns (TLS, production server, dashboard access)
rather than cryptographic ones.

## 10. References

1. H. Krawczyk, M. Bellare, R. Canetti, "HMAC: Keyed-Hashing for Message Authentication," RFC 2104, 1997.
2. NIST, "The Keyed-Hash Message Authentication Code (HMAC)," FIPS PUB 198-1, 2008.
3. Michail et al., "Efficient implementation of the keyed-hash message authentication code (HMAC) using the SHA-1 hash function," IEEE Conference Publication.
4. Castellon et al., "Towards an Energy-Efficient Hash-based Message Authentication Code (HMAC)," IEEE Conference Publication, 2022.
5. Farha et al., "Timestamp Scheme to Mitigate Replay Attacks in Secure ZigBee Networks," IEEE Transactions on Mobile Computing, 2020.
6. "Enhanced Timestamp Scheme for Mitigating Replay Attacks in Secure ZigBee Networks," IEEE Conference Publication, 2019.
7. Ethelbert, Moghaddam, Wieder, Yahyapour, "A JSON token-based authentication and access management schema for cloud SaaS applications," IEEE FiCloud, 2017.
8. "What a Mesh: Formal Security Analysis of WPA3 SAE Wireless Authentication"; IEEE 1609.2 Standard for Wireless Access in Vehicular Environments.
9. Standard Webhooks specification, https://www.standardwebhooks.com
10. Stripe documentation, "Check the webhook signatures," https://docs.stripe.com/webhooks
11. GitHub documentation, "Validating webhook deliveries," https://docs.github.com/webhooks
