# Vulnerable Receiver and Demo (T12, Anushka Gupte)

A deliberately insecure webhook receiver used only for the demo. It shows what happens
without WebhookGuard: the same attacks that the protected receiver rejects are accepted
here, and the damage is visible. The full step-by-step walkthrough is in `app/demo.md`.

> **Demo use only.** Never deploy it, never import it from `app/main.py`.

## What it does

`app/vulnerable_receiver.py` serves `POST /webhook` and accepts any request whose body is a
JSON object. It never inspects the `X-Webhook-*` headers, so there is no key lookup,
signature check, timestamp check or replay check. Accepted requests are appended to an
in-memory ledger so the effect of each attack can be shown.

## Interface

| Route | Behaviour |
|---|---|
| `POST /webhook` | JSON object body -> `200 {"status":"accepted","reason":"valid","event_id":...}`. Anything else -> `400 {"status":"rejected","reason":"malformed",...}` |
| `GET /ledger` | `{"count": n, "total_amount": x, "entries": [...]}` of everything acted on |
| `POST /reset` | Clears the ledger |

The response shape matches `docs/api-contract.md` section 4, so the comparison with the
protected receiver is like for like. `event_id` is echoed from `X-Webhook-Event-Id`
(or `null` if absent).

## Safeguards

- Binds to `127.0.0.1` only. There is no option to expose it on a network.
- Never reads `WEBHOOKGUARD_KEYS` or any other secret.
- Keeps state in memory only. Nothing is written to disk and there is no security log.
- Prints a `WARNING: VULNERABLE RECEIVER - DEMO ONLY` banner on start.
- Runs only when started by name; `app/main.py` must not import it.

## Run

    python -m app.vulnerable_receiver              # http://127.0.0.1:5001

| Variable | Default | Meaning |
|---|---|---|
| `VULNERABLE_PORT` | `5001` | Port to listen on (kept separate from the protected receiver on 5000) |

## Demo summary

The existing attack scripts (`attacks/forge.py`, `tamper.py`, `replay.py`, `expired.py`)
read their target from `WEBHOOKGUARD_URL`. Pointing it at port 5001 runs them against this
receiver.

| Attack | Vulnerable receiver | Protected receiver |
|---|---|---|
| Forgery | `200` accepted | `401 invalid_signature` |
| Tampering | `200` accepted (INR 5000 paid) | `401 invalid_signature` |
| Replay | `200` twice (paid twice) | `200`, then `409 replayed` |
| Expired | `200` accepted | `400 expired` |

The attack scripts print `FAIL` against the vulnerable receiver because they expect a
rejection. Here `FAIL` means the attack worked. The four attacks from an empty ledger give
`count: 5` and `total_amount: 7000`. See `app/demo.md` for the exact commands.

## Test

    python -m pytest tests/test_vulnerable_receiver.py -v
