# HMAC Signature Verification

## Overview

HMAC (Hash-based Message Authentication Code) helps verify the authenticity and integrity of webhook requests. WebhookGuard uses HMAC-related utilities to support signature generation and verification.

## How It Works

1. The sender prepares the webhook payload.
2. A signature is generated using a shared secret and the agreed signing format.
3. The receiver independently computes the expected signature.
4. The receiver compares the expected signature with the received signature.
5. The request is accepted only when verification succeeds.

## Canonicalization

Canonicalization defines how the data used for signing is represented. The sender and receiver must use the same format, field ordering, encoding, and separators.

If the signed representation differs, signature verification may fail even when the underlying JSON data appears equivalent.

## Security Considerations

- Store signing secrets in environment variables or a secret manager.
- Never commit real secrets to the repository.
- Verify signatures before processing webhook events.
- Use constant-time comparison where appropriate.
- Validate timestamps and event identifiers according to the application's protocol.
- Avoid logging secrets or sensitive payload contents.

## Testing and Troubleshooting

When signature verification fails:

1. Confirm that both sides use the same secret.
2. Check the canonicalization format.
3. Verify the payload encoding and exact bytes.
4. Confirm that the signature uses the expected algorithm and format.
5. Check whether the timestamp or event identifier fails validation.

## References

- [GitHub: Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [GitHub: Best practices for webhooks](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)
