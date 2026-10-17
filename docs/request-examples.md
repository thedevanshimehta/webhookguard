# Webhook Request Examples

This guide shows how to run the protected receiver and send signed webhook
events with the WebhookGuard command-line sender.

For the complete request contract, including headers, signing, validation
order, and response codes, see [API Contract](api-contract.md).

## Prepare the project

From the repository root, activate the virtual environment and install the
dependencies:

```bash
source .venv/Scripts/activate
python -m pip install -r requirements.txt
```

Create `.env` from the example file and generate a signing key:

```bash
cp .env.example .env
python -m keys.key_manager
```

Put the generated value in `.env`:

```env
WEBHOOKGUARD_KEYS=k1:<generated-secret>
```

The `.env` file is local configuration and must not be committed.

## Start the receiver

Open one terminal in the repository root and run:

```bash
python -m app.main
```

The default protected endpoint is:

```text
http://127.0.0.1:5000/webhook
```

Keep this terminal running while sending requests from a second terminal.

## Send a valid payment event

In a second terminal, from the repository root, run:

```bash
python -m sender.cli --event payment.success --amount 500 --currency INR
```

The CLI generates an event ID, signs the request using the configured key, and
sends it to the default endpoint. A successful request prints output similar
to:

```text
Event ID: evt_<generated-id>
Timestamp: <unix-timestamp>
HTTP status: 200
Response: {"event_id":"evt_<generated-id>","reason":"valid","status":"accepted"}
```

The exact event ID and timestamp vary for every request.

## Send a custom event

The sender supports a custom event name, amount, currency, and order ID:

```bash
python -m sender.cli \
  --event order.shipped \
  --amount 1250 \
  --currency INR \
  --order-id ord_demo_001
```

To send to a receiver on a different host or port, use `--url`:

```bash
python -m sender.cli \
  --url http://127.0.0.1:5050/webhook \
  --event payment.success \
  --amount 500
```

The URL must point to the receiver's `/webhook` endpoint.

## Inspect accepted payments

The demo application exposes the payments that passed verification:

```text
http://127.0.0.1:5000/ledger
```

With PowerShell, use `curl.exe` to make an HTTP request:

```powershell
curl.exe http://127.0.0.1:5000/ledger
```

Reset the demo ledger between runs:

```powershell
curl.exe -X POST http://127.0.0.1:5000/reset
```

The security dashboard is available at:

```text
http://127.0.0.1:5000/dashboard
```

## Expected rejection examples

The receiver returns a rejection when a request fails one of its checks. The
main response categories are:

| Situation | HTTP status | Reason |
|---|---:|---|
| Missing or malformed request data | 400 | `malformed` |
| Unknown key or invalid HMAC signature | 401 | `invalid_signature` |
| Timestamp outside the allowed window | 400 | `expired` |
| Same event ID submitted again | 409 | `replayed` |
| Event store unavailable | 503 | `store_unavailable` |
| Request body exceeds the configured limit | 413 | `too_large` |

For example, sending the same signed event twice causes the first delivery to
be accepted and the second delivery to be rejected as a replay. The sender CLI
generates a new event ID for each invocation, so use one of the attack scripts
when testing a deliberate replay.

## Compare protected and vulnerable demo receivers

The repository includes a deliberately unsafe receiver for the local attack
demonstration only. Start it separately on port 5001:

```bash
python -m app.vulnerable_receiver
```

The protected receiver remains on port 5000. The full comparison procedure and
attack commands are documented in [Demo: Vulnerable vs Protected Receiver](../app/demo.md).

Never deploy or expose the vulnerable receiver.
