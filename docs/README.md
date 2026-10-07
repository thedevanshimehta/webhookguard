# Docs
Each module owner adds a short section here (what it does, interface, how to test).
Planned files: `api-contract.md`, one `<module>.md` per owner, `attack-results.md`, `final-report.md`.

## Security dashboard (T18, Sampada Daware)

Read-only observability over the existing security log (`LOG_PATH`, JSON lines per api-contract.md section 7). The dashboard never verifies anything itself and never displays secrets, signatures or payload contents (payloads appear only as `body_sha256`).

| Route | Purpose |
|---|---|
| `GET /dashboard` | Dashboard page (`logs-dashboard/dashboard.html`, plain HTML/CSS/JS) |
| `GET /api/dashboard` | Aggregated log data: total/valid/rejected counts, per-reason breakdown, 100 most recent events |
| `GET /api/health` | Real status only: process up + log file reachable |

Note: the receiver cannot cryptographically distinguish forged from tampered requests (both fail the HMAC, contract section 4), so the dashboard shows one category, **Forged / Tampered** (`invalid_signature`).

Test:

```bash
python -m app.main                 # starts receiver + dashboard on :5000
# then open http://127.0.0.1:5000/dashboard
```

`logs-dashboard/logger.py` (T14) is the writer: one JSON object per decision, appended to `LOG_PATH`, missing fields `null`, write failures logged to stderr and never surfaced as webhook errors. The `logs-dashboard/` directory name is hyphenated (not importable as a package), so `app/wg_modules.py` loads these two modules from their real paths under fixed module names.
