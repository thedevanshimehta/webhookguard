# WebhookGuard

**Team: Not Today, Hackers!** | Applied Cryptography and Network Security Design Challenge (ACNS-DC) 2026-27
Sardar Patel Institute of Technology, Mumbai | Course CE305/CS305

A receiver-side security layer that checks every incoming webhook before the application acts on it. It defends against **forged**, **tampered**, **replayed** and **expired** webhook requests using HMAC-SHA256 signatures, timestamp windows and event-ID tracking.

## The problem
Webhooks are automatic server-to-server HTTP calls (payment success, order updates, deployments). If the receiver trusts them blindly, an attacker can:

| Attack | Example | Defence |
|--------|---------|---------|
| Forgery | Fake `payment.success` event | HMAC signature with shared secret |
| Tampering | Change amount from Rs 500 to Rs 5000 | Signature covers the full body |
| Replay | Resend a captured valid request | Unique `event_id` store |
| Expired request | Reuse an old valid request later | Timestamp window (5 min) |

## How it works
The sender signs `timestamp + event_id + body` with HMAC-SHA256. The receiver runs the checks in order and stops at the first failure:

```
POST /webhook
   -> 1. Signature check   (forged / tampered?)   -> reject
   -> 2. Timestamp check   (expired / future?)    -> reject
   -> 3. Replay check      (event_id seen?)       -> reject
   -> 4. Accept, forward to application
Every decision is written to the security log, which feeds the dashboard.
```

## Repository structure
```
webhookguard/
├── README.md
├── CONTRIBUTING.md
├── requirements.txt
├── .env.example
├── .github/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── ISSUE_TEMPLATE/task.md
├── sender/                 # Webhook sender (signs and POSTs events)
├── receiver/
│   ├── crypto/             # Canonical message + HMAC utilities
│   └── pipeline/           # Endpoint, signature/timestamp/replay checks, decision engine
├── store/                  # Event ID store (Redis or SQLite)
├── keys/                   # Key management and rotation
├── logs-dashboard/         # Security logger and dashboard page
├── app/                    # Entrypoint, config, vulnerable receiver, demo
├── attacks/                # Forgery, tampering, replay and expiry scripts
├── tests/                  # Unit and integration tests
└── docs/                   # API contract, module docs, attack results, final report
```

## Quick start
> Commands become final once the entrypoint (T04) is merged.

```bash
git clone <repo-url> && cd webhookguard
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # then set a real secret
python -m app.main                                    # start the protected receiver
python -m sender.cli --event payment.success --amount 500   # send a signed event
pytest tests/ -v
```

## Team and ownership
| ID | Member | Module | Main files |
|----|--------|--------|-----------|
| T01-T02 | Devanshi Mehta (Lead) | Repo, API contract | `README.md`, `docs/api-contract.md` |
| T03 | Devanshi Mehta | Key management | `keys/key_manager.py` |
| T04 | Devanshi Mehta | App entrypoint and config | `app/main.py`, `app/config.py` |
| T05-T06 | Devanshi Mehta | Integration, final report | `docs/final-report.md` |
| T07 | Laxmi Angadi | Canonicalization and HMAC | `receiver/crypto/hmac_utils.py` |
| T08 | Laxmi Angadi | Integration tests | `tests/test_integration.py` |
| T09 | Suhana Asrani | Webhook sender | `sender/sender.py`, `sender/cli.py` |
| T10 | Vedansh Gholba | Endpoint and signature check | `receiver/pipeline/endpoint.py`, `signature_check.py` |
| T11 | Anushka Gupte | Timestamp validation | `receiver/pipeline/timestamp_check.py` |
| T12 | Anushka Gupte | Vulnerable receiver and demo | `app/vulnerable_receiver.py`, `app/demo.md` |
| T13 | Yashvi Dalal | Replay detection and event store | `store/event_store.py`, `receiver/pipeline/replay_check.py` |
| T14 | Harsh Ghole | Decision engine and logging | `receiver/pipeline/decision_engine.py`, `logs-dashboard/logger.py` |
| T15 | Laksh Nagrare | Forgery and tampering attacks | `attacks/forge.py`, `attacks/tamper.py` |
| T16-T17 | Gurshaan Nandrajog | Replay/expiry attacks, results table | `attacks/replay.py`, `attacks/expired.py`, `docs/attack-results.md` |
| T18 | Sampada Daware | Security dashboard | `logs-dashboard/dashboard.html` |

Full schedule, dependencies and status are in the task plan spreadsheet (`WebhookGuard_Task_Plan.xlsx`).

## Timeline (2-week sprint)
| Days | Milestone |
|------|-----------|
| 1-2 | Repo, API contract and log schema frozen |
| 3-6 | Core modules: HMAC, sender, endpoint, timestamp, replay, key manager |
| 7-9 | Decision engine, entrypoint, attack scripts, dashboard |
| 10 | Integration, tests, vulnerable-vs-protected demo |
| 11-12 | Attack results, docs, final report |
| 13-14 | Buffer (fixes only) |

## Contributing
Read [CONTRIBUTING.md](CONTRIBUTING.md) first: branch from `dev`, one task per `feature/*` branch, PR into `dev` with one approval.

## References
See `docs/` and the references section of the project's Problem Understanding and Solution Approach document.
