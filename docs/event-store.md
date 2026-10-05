# Event Store and Replay Check (T13, Yashvi Dalal)

## Interface (propose for api-contract.md section 4, "event_store")

```python
class EventStore:
    def check_and_set(self, event_id: str, ttl_seconds: float) -> bool
        # True  = event_id is new (now recorded for ttl_seconds)
        # False = already seen and not expired -> replay
        # raises StoreUnavailable if the backend is down
    def purge_expired(self) -> int
    def close(self) -> None

create_event_store(kind="sqlite" | "redis" | "memory", path=..., redis_url=...)
```

```python
# receiver/pipeline/replay_check.py
check_replay(event_id, store, *, window_seconds=300, future_skew_seconds=300, key_id=None)
    -> ReplayResult(passed: bool, reason: str, http_status: int)
# valid -> (True, "valid", 200) | replay -> (False, "replayed", 409)
# store down -> (False, "store_unavailable", 503)   [fails closed]
```

## For the decision engine (T14, Harsh)

Call order must be signature -> timestamp -> replay. The replay check *records* the
event ID, so running it before authentication would let an unauthenticated attacker
burn real event IDs. Only validly signed, fresh requests may reach it.

## Design notes

- **Atomic**: Redis `SET NX PX`; SQLite single `INSERT ... ON CONFLICT DO UPDATE ... WHERE expires_at <= now`.
  Tested with 32 simultaneous threads: exactly one wins.
- **TTL = window + future skew + 30 s margin (630 s with defaults)**, not just the window.
  A request stamped up to 300 s in the future stays timestamp-valid until ts + 300 s.
- **Persistent** (SQLite file / Redis): a restart does not reopen the replay window.
- **Fails closed**: store unreachable -> reject with 503, never accept unchecked.
- **key_id namespacing** (optional): two senders reusing an event_id do not collide.

## Config the entrypoint (T04) needs

`EVENT_STORE=redis|sqlite|memory`, `EVENT_STORE_PATH=data/events.db`, `REDIS_URL=redis://localhost:6379/0`,
window and future skew must be the same values T11 (timestamp check) uses.

## Test

    pip install -r requirements.txt
    python -m pytest tests/test_replay.py -v
    python -m store.demo_replay [sqlite|redis|memory]

## Stress test

    python -m tests.stress_replay                      # sqlite, 100k events, 15% replays, 8 threads
    python -m tests.stress_replay --backend redis
    python -m tests.stress_replay --events 200000 --dup-ratio 0.2 --threads 16

Result in the dev sandbox (115,000 requests, 15,000 deliberate replays, 8 threads):
exactly 100,000 accepted and 15,000 rejected on memory, SQLite and Redis.
Throughput (dev sandbox): memory ~423k req/s, SQLite ~28k req/s, Redis ~4.6k req/s (numbers vary by machine; Windows is slower).
