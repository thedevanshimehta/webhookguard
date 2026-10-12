# WebhookGuard Attack Results

## 1. Purpose

This document records the expected outcomes of the WebhookGuard attack demonstrations and the status of their verification. Expected outcomes are based on `docs/api-contract.md`. Results are not marked as observed unless confirmed by running the attack against a working receiver.

## 2. Attack Results

| Task | Attack | Expected HTTP Status | Expected Reason | Verification Status |
|---|---|---:|---|---|
| T15 | Forged signature | 401 | `invalid_signature` | Live receiver verification pending |
| T15 | Tampered payload | 401 | `invalid_signature` | Live receiver verification pending |
| T16 | Replayed webhook | 409 on second delivery | `replayed` | Live receiver verification pending |
| T16 | Expired timestamp | 400 | `expired` | Live receiver verification pending |

## 3. Attack Descriptions

### T15: Forged Signature

The forgery script signs a request using an incorrect secret while retaining the configured key ID. The receiver is expected to reject the request because its signature does not match.

Expected response: HTTP 401 with reason `invalid_signature`.

### T15: Tampered Payload

The tampering script first signs a payment payload for INR 500, then changes the amount to INR 5000 without updating the signature. The receiver is expected to reject the modified payload.

Expected response: HTTP 401 with reason `invalid_signature`.

### T16: Replayed Webhook

The replay script sends the same signed request twice using the same event ID. The first delivery is expected to be accepted, and the duplicate delivery is expected to be rejected.

Expected responses: HTTP 200 with reason `valid` on the first delivery, followed by HTTP 409 with reason `replayed`.

### T16: Expired Timestamp

The expired-timestamp script creates a correctly signed request with a timestamp older than the configured freshness window. The default window is 300 seconds.

Expected response: HTTP 400 with reason `expired`.

## 4. Test Status and Limitations

The existing replay and timestamp unit tests previously ran with 42 passed and 4 skipped. Syntax checks for the T16 attack scripts also passed.

These checks do not establish that the attack scripts succeed against a running HTTP receiver. Live end-to-end verification remains pending because required receiver modules were missing from the inspected `dev` checkout.

Update the verification status and record actual HTTP responses after the receiver is available and the attack scripts have been run.

## 5. API Contract Reference

Expected HTTP statuses and reason codes are taken from `docs/api-contract.md`, Section 4 (Responses). The verification order follows Section 3, and timestamp freshness follows Section 5.