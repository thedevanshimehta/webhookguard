# WebhookGuard Demo: Vulnerable vs Protected Receiver (T12)

The same four attack scripts (`attacks/forge.py`, `tamper.py`, `replay.py`, `expired.py`) are run
against two receivers. Only the target changes.

| | Vulnerable receiver | Protected receiver (WebhookGuard) |
|---|---|---|
| Code | `app/vulnerable_receiver.py` | `app/main.py` -> `receiver/pipeline/endpoint.py` + `decision_engine.py` |
| Port | 5001 | 5000 |
| Checks | none | key lookup, HMAC signature, timestamp window, replay |

> The vulnerable receiver is for this demo only. It binds to `127.0.0.1`, never reads
> your secrets, and must never be deployed or imported by `app/main.py`.

## 0. Setup

```
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
```

Put a real key in `.env`. Generate a secret with `python -m keys.key_manager` and set
`WEBHOOKGUARD_KEYS=k1:<that secret>`. The example placeholder is refused on purpose.
For a clean demo you can also set `EVENT_STORE=memory` so no database file is created.

The receiver, the sender CLI and the attack scripts all read `.env`, so nothing has to be
exported in the shell.

Open **three terminals** in the repo root.

**Terminal 1: protected receiver (port 5000)**
```
python -m app.main
```
It prints the dashboard address: http://127.0.0.1:5000/dashboard. Open it in a browser and
keep it visible; it refreshes every 3 seconds.

**Terminal 2: vulnerable receiver (port 5001)**
```
python -m app.vulnerable_receiver
```
It prints a `WARNING: VULNERABLE RECEIVER - DEMO ONLY` banner.

**Terminal 3: attacker.** All commands below run here.

## 1. A legitimate webhook (control test)

Send one genuine signed payment to each receiver:
```
python -m sender.cli --url http://127.0.0.1:5000/webhook
python -m sender.cli --url http://127.0.0.1:5001/webhook
```

Both return `HTTP status: 200` with `"status":"accepted"`. Real traffic works on both, so the
difference in the next steps comes from the attacks and not from a broken setup.

## 2. Attacks on the vulnerable receiver

The attack scripts read their target from the `WEBHOOKGUARD_URL` environment variable
(default: the protected receiver on port 5000). Point it at the vulnerable receiver:

| Shell | Command |
|---|---|
| macOS / Linux / Git Bash | `export WEBHOOKGUARD_URL=http://127.0.0.1:5001/webhook` |
| Windows PowerShell | `$env:WEBHOOKGUARD_URL = "http://127.0.0.1:5001/webhook"` |
| Windows cmd | `set WEBHOOKGUARD_URL=http://127.0.0.1:5001/webhook` |

Each script prints `Target: ...` when it starts. Check it says port 5001. Then run:

```
python -m attacks.forge
python -m attacks.tamper
python -m attacks.replay
python -m attacks.expired
```

Every attack is accepted. For example, the forgery attack prints:

```
Attack: forged HMAC using an incorrect secret
Target: http://127.0.0.1:5001/webhook

[forgery] HTTP 200
{
  "event_id": "evt_...",
  "reason": "valid",
  "status": "accepted"
}
FAIL: Forgery attack expected HTTP 401 / invalid_signature, received HTTP 200, reason='valid'
```

**The `FAIL` lines are the point.** The scripts are written to expect a rejection, so against a
receiver with no protection they report `FAIL` and exit with an error. In plain words, `FAIL`
here means the attack worked.

| Script | Against the vulnerable receiver |
|---|---|
| `attacks.forge` | `HTTP 200`, then `FAIL: ... expected HTTP 401 / invalid_signature` |
| `attacks.tamper` | `HTTP 200`, then `FAIL: ... expected HTTP 401 / invalid_signature` |
| `attacks.replay` | both deliveries `HTTP 200`, then `FAIL: expected 200/valid, followed by 409/replayed.` |
| `attacks.expired` | `HTTP 200`, then `FAIL: expected HTTP 400 / expired, received HTTP 200 / 'valid'.` |

### See the damage

Terminal 2 prints a `[VULNERABLE] ACCEPTED` line for every request. The receiver also keeps a
ledger of everything it acted on. Open this in a browser, or fetch it with curl:

```
http://127.0.0.1:5001/ledger
curl http://127.0.0.1:5001/ledger        # Windows PowerShell: curl.exe
```

After the four attacks (plus the control test, if you ran it) the ledger shows:

- the forged payment, paid out
- the tampered payment, paid out as INR 5000 instead of INR 500
- the replayed payment, paid out twice
- the expired payment, paid out

Starting from an empty ledger, the four attacks alone give `count: 5` and `total_amount: 7000`.
The attacker needed no secret at all.

## 3. The same attacks on the protected receiver

Point the scripts back at the protected receiver. Either remove the variable or set it to port 5000:

| Shell | Command |
|---|---|
| macOS / Linux / Git Bash | `unset WEBHOOKGUARD_URL` |
| Windows PowerShell | `Remove-Item Env:WEBHOOKGUARD_URL` |
| Windows cmd | `set WEBHOOKGUARD_URL=` |

Run the same four commands:

```
python -m attacks.forge
python -m attacks.tamper
python -m attacks.replay
python -m attacks.expired
```

| Attack | What the attacker does | Protected receiver response | Which check stops it |
|---|---|---|---|
| Forgery (`forge`) | Signs with a wrong secret | `401 invalid_signature` | HMAC signature check |
| Tampering (`tamper`) | Changes INR 500 to INR 5000, keeps the old signature | `401 invalid_signature` | HMAC signature check |
| Replay (`replay`) | Sends the same signed request twice | 1st `200 valid`, 2nd `409 replayed` | Replay check (event ID store) |
| Expired (`expired`) | Correctly signed, but older than the window | `400 expired` | Timestamp check |

Now every script prints `PASS`, for example `PASS: Forgery attack rejected with invalid_signature`,
`PASS: replay correctly rejected.` and `PASS: expired request rejected.`, and exits cleanly.

Forgery and tampering both fail the HMAC, so the receiver cannot tell them apart and uses
one code, `invalid_signature` (contract section 4). The dashboard shows it as "Forged / Tampered".

### See the damage prevented

The protected receiver forwards accepted events to a demo payments application with the same
ledger view. Reset it first (`curl -X POST http://127.0.0.1:5000/reset`) for a clean count, run
the four attacks, then open:

```
http://127.0.0.1:5000/ledger
```

Only the replay script's first, genuine delivery appears: `count: 1`, `total_amount: 500`.
Compare it with the vulnerable receiver's `count: 5`, `total_amount: 7000`. The dashboard at
http://127.0.0.1:5000/dashboard shows every attempt and why it was rejected.

## 4. Evidence in the security log

The protected receiver writes one JSON line per decision to `LOG_PATH` (default
`logs/security.jsonl`):

```
cat logs/security.jsonl            # Windows: type logs\security.jsonl
```

You should see entries like these (values will differ):

```json
{"event_id": "evt_...", "key_id": "k1", "decision": "rejected", "reason": "invalid_signature", ...}
{"event_id": "evt_...", "key_id": "k1", "decision": "accepted", "reason": "valid", ...}
{"event_id": "evt_...", "key_id": "k1", "decision": "rejected", "reason": "replayed", ...}
{"event_id": "evt_...", "key_id": "k1", "decision": "rejected", "reason": "expired", ...}
```

The log holds hashes and metadata only: no secrets, no full signatures and no raw bodies.
The vulnerable receiver keeps no security log, so the attacks leave no trace there.

## 5. Why the protection works

| Question | Protected receiver | Vulnerable receiver |
|---|---|---|
| Is the sender who they claim? | HMAC-SHA256 over `timestamp.event_id.body` with a secret only the sender has | Not checked |
| Was the body changed? | The body is part of the signed data, so any change breaks the signature | Not checked |
| Is it fresh? | Must be within 300 s of the receiver's clock, in both directions | Not checked |
| Has it been seen before? | Event ID stored (atomically) only after signature and timestamp pass | Not checked |

The order matters: cheap checks run first, and an event ID is stored only after the request has
proven authentic, so an attacker cannot fill the store with fake IDs.

## 6. Reset and clean up

Clear the ledgers between runs:
```
curl -X POST http://127.0.0.1:5001/reset        # vulnerable; Windows PowerShell: curl.exe -X POST ...
curl -X POST http://127.0.0.1:5000/reset        # protected
```

Stop both receivers with Ctrl+C. If you used SQLite, the event store file (`data/events.db`
by default) is local state; do not commit it.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Could not reach receiver at ...` | Start that receiver first, and check `WEBHOOKGUARD_URL` points at the right port. |
| Attacks accepted when you expected rejection (or the reverse) | Check the `Target:` line the script prints. A leftover `WEBHOOKGUARD_URL` in your shell is the usual cause. |
| Sender, attack script or receiver reports a key configuration error | Set `WEBHOOKGUARD_KEYS` in `.env` to a generated secret (`python -m keys.key_manager`). The example placeholder is refused. |
| Genuine sender gets `401 invalid_signature` | Look at the last line of `logs/security.jsonl`. If it says `unknown_key`, the sender and receiver use different `WEBHOOKGUARD_KEYS` (the client is not told, on purpose). Restart both after editing `.env`. |
| `413 too_large` | The body is bigger than `MAX_BODY_BYTES` (default 1 MiB). |
| `ModuleNotFoundError` | Run commands from the repo root with `python -m ...`. |
