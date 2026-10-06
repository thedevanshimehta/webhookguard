"""Event store: remembers which event IDs have already been processed.

Owner: Yashvi Dalal (T13).  Branch: feature/replay-check

The whole replay defence rests on ONE operation:

    check_and_set(event_id, ttl_seconds) -> bool

    True  -> event_id was NOT seen before (now recorded, remembered for ttl_seconds)
    False -> event_id was already seen and has not expired  => REPLAY

"Check" and "set" happen as a single atomic step.  A separate
`if not exists(id): add(id)` would be a race: two receiver instances (or two
threads) could both see "not exists" and both accept the same webhook.

Backends (same interface, pick via create_event_store / config):
    * RedisEventStore   - SET key NX EX ttl           (shared across instances)
    * SQLiteEventStore  - single upsert statement     (fallback, single host)
    * InMemoryEventStore - dict + lock                (tests / stubs only)

Failure policy: if the backend is unreachable we raise StoreUnavailable.
The caller (replay_check) fails CLOSED - an event we cannot verify as new is
not accepted.
"""

from __future__ import annotations

import math
import os
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from typing import Callable, Optional

Clock = Callable[[], float]


class StoreUnavailable(Exception):
    """The backing store could not be reached or failed."""


class EventStore(ABC):
    """Interface every backend implements."""

    @abstractmethod
    def check_and_set(self, event_id: str, ttl_seconds: float) -> bool:
        """Atomically record event_id. Return True if new, False if duplicate."""

    def purge_expired(self) -> int:
        """Delete expired entries. Returns number removed (0 if backend self-expires)."""
        return 0

    def close(self) -> None:
        """Release resources."""

    @staticmethod
    def _validate(event_id: str, ttl_seconds: float) -> None:
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("event_id must be a non-empty string")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")


# --------------------------------------------------------------------------- #
# In-memory (tests / stubs)
# --------------------------------------------------------------------------- #
class InMemoryEventStore(EventStore):
    """Process-local store. NOT for production: lost on restart, not shared
    between instances (both reopen the replay window)."""

    def __init__(self, clock: Clock = time.time):
        self._clock = clock
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_set(self, event_id: str, ttl_seconds: float) -> bool:
        self._validate(event_id, ttl_seconds)
        now = self._clock()
        with self._lock:
            expires = self._seen.get(event_id)
            if expires is not None and expires > now:
                return False
            self._seen[event_id] = now + ttl_seconds
            return True

    def purge_expired(self) -> int:
        now = self._clock()
        with self._lock:
            dead = [k for k, exp in self._seen.items() if exp <= now]
            for k in dead:
                del self._seen[k]
            return len(dead)


# --------------------------------------------------------------------------- #
# SQLite (fallback)
# --------------------------------------------------------------------------- #
class SQLiteEventStore(EventStore):
    """File-backed store; survives restarts, safe across threads/processes on
    one host.  Atomicity comes from a single upsert statement:

        INSERT ... ON CONFLICT(event_id) DO UPDATE ... WHERE expires_at <= now

    rowcount == 1  -> row inserted (new) or an EXPIRED row was reused (new)
    rowcount == 0  -> live row exists (duplicate)
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS seen_events (
            event_id   TEXT PRIMARY KEY,
            expires_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_seen_expires ON seen_events(expires_at);
    """
    _UPSERT = """
        INSERT INTO seen_events (event_id, expires_at) VALUES (?, ?)
        ON CONFLICT(event_id) DO UPDATE SET expires_at = excluded.expires_at
        WHERE seen_events.expires_at <= ?
    """

    def __init__(self, path: str = "data/events.db", clock: Clock = time.time,
                 purge_every: int = 500):
        self._path = path
        self._clock = clock
        self._purge_every = purge_every
        self._calls = 0
        self._calls_lock = threading.Lock()
        self._local = threading.local()   # sqlite connections are per-thread
        self._conns: list[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()
        if path != ":memory:":
            d = os.path.dirname(os.path.abspath(path))
            os.makedirs(d, exist_ok=True)
        try:
            self._conn().executescript(self._SCHEMA)
        except sqlite3.Error as e:
            raise StoreUnavailable(f"cannot open SQLite store: {e}") from e

    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self._path, timeout=10, isolation_level=None)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=10000")
            c.execute("PRAGMA synchronous=NORMAL")  # safe with WAL; far fewer fsyncs
            self._local.conn = c
            with self._conns_lock:
                self._conns.append(c)
        return c

    def check_and_set(self, event_id: str, ttl_seconds: float) -> bool:
        self._validate(event_id, ttl_seconds)
        now = self._clock()
        is_new = self._execute_upsert(event_id, now, ttl_seconds)
        self._maybe_purge()
        return is_new

    # Transient errors seen on Windows / network or synced drives (file locking,
    # antivirus, OneDrive).  Safe to retry: a failed statement is rolled back,
    # so the event is either recorded once or not at all.
    _TRANSIENT = ("locked", "busy", "disk i/o error")
    _MAX_ATTEMPTS = 6

    def _execute_upsert(self, event_id: str, now: float, ttl_seconds: float) -> bool:
        last: Optional[sqlite3.Error] = None
        for attempt in range(self._MAX_ATTEMPTS):
            try:
                cur = self._conn().execute(self._UPSERT, (event_id, now + ttl_seconds, now))
                return cur.rowcount == 1
            except sqlite3.Error as e:
                last = e
                if not any(t in str(e).lower() for t in self._TRANSIENT):
                    break                                  # not transient: fail now
                time.sleep(0.02 * (2 ** attempt))          # 20ms .. 640ms backoff
        raise StoreUnavailable(f"SQLite error: {last}") from last

    def _maybe_purge(self) -> None:
        with self._calls_lock:
            self._calls += 1
            due = self._calls % self._purge_every == 0
        if due:
            try:
                self.purge_expired()
            except StoreUnavailable:
                pass  # housekeeping only; never fail a request for it

    def purge_expired(self) -> int:
        try:
            cur = self._conn().execute(
                "DELETE FROM seen_events WHERE expires_at <= ?", (self._clock(),))
            return cur.rowcount
        except sqlite3.Error as e:
            raise StoreUnavailable(f"SQLite error: {e}") from e

    def close(self) -> None:
        with self._conns_lock:
            for c in self._conns:
                try:
                    c.close()
                except sqlite3.Error:
                    pass
            self._conns.clear()
        self._local = threading.local()


# --------------------------------------------------------------------------- #
# Redis (preferred if the team runs it)
# --------------------------------------------------------------------------- #
class RedisEventStore(EventStore):
    """Shared across receiver instances.  `SET key 1 NX EX ttl` is atomic in
    Redis and expires by itself, so there is nothing to purge."""

    def __init__(self, client=None, url: str = "redis://localhost:6379/0",
                 prefix: str = "wg:event:"):
        if client is None:
            import redis  # imported lazily so SQLite-only setups need no redis package
            client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
        self._r = client
        self._prefix = prefix

    def check_and_set(self, event_id: str, ttl_seconds: float) -> bool:
        self._validate(event_id, ttl_seconds)
        try:
            ok = self._r.set(self._prefix + event_id, 1, nx=True,
                             px=max(1, math.ceil(ttl_seconds * 1000)))
        except Exception as e:  # redis.RedisError and connection errors
            raise StoreUnavailable(f"Redis error: {e}") from e
        return bool(ok)

    def close(self) -> None:
        try:
            self._r.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
def create_event_store(kind: str = "sqlite", *, path: str = "data/events.db",
                       redis_url: str = "redis://localhost:6379/0",
                       clock: Optional[Clock] = None) -> EventStore:
    """Build a store from config.  kind: 'redis' | 'sqlite' | 'memory'."""
    clock = clock or time.time
    kind = kind.lower()
    if kind == "redis":
        return RedisEventStore(url=redis_url)
    if kind == "sqlite":
        return SQLiteEventStore(path=path, clock=clock)
    if kind == "memory":
        return InMemoryEventStore(clock=clock)
    raise ValueError(f"unknown event store kind: {kind!r}")
