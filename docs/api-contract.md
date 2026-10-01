# API Contract (owner: Devanshi, task T02, due Day 2)

> Placeholder. Replace with the agreed contract before anyone starts coding against it.

## 1. Webhook request (`POST /webhook`)
- Headers / body fields: `payload`, `timestamp`, `event_id`, `signature`, (optional) `key_id`
- Canonical message format: _TBD_ (timestamp + event_id + body)
- Signature: HMAC-SHA256, hex encoded

## 2. Receiver responses
| Case | HTTP status | Reason code |
|------|-------------|-------------|
| Valid | 200 | `valid` |
| Bad signature (forged/tampered) | 401 | `forged` / `tampered` |
| Outside time window | 400 | `expired` |
| Duplicate event_id | 409 | `replayed` |

## 3. Security log entry (JSON lines)
_TBD_ (timestamp, event_id, decision, reason, source_ip, key_id)

## 4. Interfaces between modules
- `hmac_utils`: _TBD_
- `key_manager`: `get_key(key_id)`, `get_active_keys()`
- `event_store`: _TBD_ (atomic check-and-set)
- `decision_engine`: _TBD_
