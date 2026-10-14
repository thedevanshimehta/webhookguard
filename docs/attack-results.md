# WebhookGuard Attack Results

## 1. Purpose

This document records the outcomes of the WebhookGuard attack demonstrations. Expected outcomes are based on `docs/api-contract.md`. A result is marked as observed only when it was confirmed by running the attack against a working receiver.

## 2. Attack Results

| Task | Attack | Expected HTTP Status | Expected Reason | Observed (protected receiver) | Observed (vulnerable receiver) |
|---|---|---:|---|---|---|
| T15 | Forged signature | 401 | `invalid_signature` | 401 `invalid_signature`, PASS | 200 accepted |
| T15 | Tampered payload | 401 | `invalid_signature` | 401 `invalid_signature`, PASS | 200 accepted (paid INR 5000) |
| T16 | Replayed webhook | 409 on second delivery | `replayed` | 200, then 409 `replayed`, PASS | 200, 200 (paid twice) |
| T16 | Expired timestamp | 400 | `expired` | 400 `expired`, PASS | 200 accepted |

Observed on 2026-10-13 with `python -m app.main` (port 5000) and `python -m app.vulnerable_receiver` (port 5001), following `app/demo.md`. After the four attacks:
- the vulnerable receiver's `/ledger` showed 5 payouts totalling INR 7000;
- the protected receiver's `/ledger` showed only the genuine payments.

## 3. Attack Descriptions

### T15: Forged Signature

The forgery script signs a request using an incorrect secret while retaining the configured key ID. The receiver rejects the request because its signature does not match.

Expected response: HTTP 401 with reason `invalid_signature`.

### T15: Tampered Payload

The tampering script first signs a payment payload for INR 500, then changes the amount to INR 5000 without updating the signature. The receiver rejects the modified payload.

Expected response: HTTP 401 with reason `invalid_signature`.

### T16: Replayed Webhook

The replay script sends the same signed request twice using the same event ID. The first delivery is accepted, and the duplicate delivery is rejected.

Expected responses: HTTP 200 with reason `valid` on the first delivery, followed by HTTP 409 with reason `replayed`.

### T16: Expired Timestamp

The expired-timestamp script creates a correctly signed request with a timestamp older than the configured freshness window. The default window is 300 seconds.

Expected response: HTTP 400 with reason `expired`.

## 4. Test Status

The same four attacks also run automatically, in process, in `tests/test_end_to_end.py` (see `docs/integration.md`). The full suite (`python -m pytest tests/`) passes, including the Redis backend tests when `fakeredis` is installed.

## 5. API Contract Reference

Expected HTTP statuses and reason codes are taken from `docs/api-contract.md`, Section 4 (Responses). The verification order follows Section 3, and timestamp freshness follows Section 5.
