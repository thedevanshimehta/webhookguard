"""Tests for T13: event store + replay check.

Run from the repo root:   python -m pytest tests/test_replay.py -v
Redis tests use fakeredis (pip install fakeredis); skipped if not installed.
"""

import threading

import pytest

from receiver.pipeline.replay_check import (check_replay, ttl_for_window,
                                            REASON_REPLAYED, REASON_STORE_ERROR,
                                            REASON_VALID)
from store.event_store import (InMemoryEventStore, RedisEventStore,
                               SQLiteEventStore, StoreUnavailable,
                               create_event_store)


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def _redis_store(clock):
    fakeredis = pytest.importorskip("fakeredis")
    # fakeredis expiry follows real time, so TTL-expiry tests use sqlite/memory
    return RedisEventStore(client=fakeredis.FakeRedis())


@pytest.fixture(params=["memory", "sqlite", "redis"])
def store_and_clock(request, tmp_path):
    clock = FakeClock()
    if request.param == "memory":
        s = InMemoryEventStore(clock=clock)
    elif request.param == "sqlite":
        s = SQLiteEventStore(path=str(tmp_path / "e.db"), clock=clock)
    else:
        s = _redis_store(clock)
    yield request.param, s, clock
    s.close()


# ---- behaviour every backend must share -------------------------------------
def test_first_time_is_new_second_is_duplicate(store_and_clock):
    _, s, _ = store_and_clock
    assert s.check_and_set("evt_1", 60) is True
    assert s.check_and_set("evt_1", 60) is False
    assert s.check_and_set("evt_1", 60) is False


def test_different_ids_are_independent(store_and_clock):
    _, s, _ = store_and_clock
    assert s.check_and_set("evt_a", 60) is True
    assert s.check_and_set("evt_b", 60) is True


def test_rejects_bad_input(store_and_clock):
    _, s, _ = store_and_clock
    with pytest.raises(ValueError):
        s.check_and_set("", 60)
    with pytest.raises(ValueError):
        s.check_and_set("evt", 0)


# ---- TTL expiry (clock-controlled backends) ---------------------------------
@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_entry_expires_after_ttl(kind, tmp_path):
    clock = FakeClock()
    s = (InMemoryEventStore(clock=clock) if kind == "memory"
         else SQLiteEventStore(path=str(tmp_path / "t.db"), clock=clock))
    assert s.check_and_set("evt_1", 100) is True
    clock.advance(99)
    assert s.check_and_set("evt_1", 100) is False      # still remembered
    clock.advance(2)                                     # now past TTL
    assert s.check_and_set("evt_1", 100) is True       # forgotten -> new again
    assert s.check_and_set("evt_1", 100) is False
    s.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_purge_removes_only_expired(kind, tmp_path):
    clock = FakeClock()
    s = (InMemoryEventStore(clock=clock) if kind == "memory"
         else SQLiteEventStore(path=str(tmp_path / "p.db"), clock=clock))
    s.check_and_set("old", 10)
    s.check_and_set("fresh", 1000)
    clock.advance(11)
    assert s.purge_expired() == 1
    assert s.check_and_set("fresh", 1000) is False
    s.close()


def test_sqlite_survives_restart(tmp_path):
    p = str(tmp_path / "persist.db")
    a = SQLiteEventStore(path=p)
    assert a.check_and_set("evt_1", 300) is True
    a.close()
    b = SQLiteEventStore(path=p)                         # simulated service restart
    assert b.check_and_set("evt_1", 300) is False        # replay window NOT reopened
    b.close()


# ---- atomicity: the core requirement ---------------------------------------
@pytest.mark.parametrize("kind", ["memory", "sqlite", "redis"])
def test_concurrent_same_event_accepted_exactly_once(kind, tmp_path):
    if kind == "memory":
        s = InMemoryEventStore()
    elif kind == "sqlite":
        s = SQLiteEventStore(path=str(tmp_path / "c.db"))
    else:
        s = _redis_store(None)
    n = 32
    barrier = threading.Barrier(n)
    results = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        r = s.check_and_set("evt_race", 60)
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(results) == n
    assert results.count(True) == 1, "exactly one request may win the race"
    s.close()


def test_two_sqlite_instances_same_file_share_state(tmp_path):
    """Simulates two receiver processes pointed at one DB file."""
    p = str(tmp_path / "shared.db")
    a, b = SQLiteEventStore(path=p), SQLiteEventStore(path=p)
    assert a.check_and_set("evt_x", 60) is True
    assert b.check_and_set("evt_x", 60) is False
    a.close(); b.close()


# ---- replay_check (pipeline step) -------------------------------------------
def test_replay_check_valid_then_replayed():
    s = InMemoryEventStore()
    r1 = check_replay("evt_1", s)
    assert r1.passed and r1.reason == REASON_VALID and r1.http_status == 200
    r2 = check_replay("evt_1", s)
    assert not r2.passed and r2.reason == REASON_REPLAYED and r2.http_status == 409


def test_replay_check_namespaces_by_key_id():
    s = InMemoryEventStore()
    assert check_replay("evt_1", s, key_id="k1").passed
    assert check_replay("evt_1", s, key_id="k2").passed        # different sender
    assert not check_replay("evt_1", s, key_id="k1").passed


def test_replay_check_fails_closed_when_store_down():
    class Broken(InMemoryEventStore):
        def check_and_set(self, *a, **k):
            raise StoreUnavailable("down")
    r = check_replay("evt_1", Broken())
    assert not r.passed and r.reason == REASON_STORE_ERROR and r.http_status == 503


def test_replay_check_rejects_empty_event_id():
    assert not check_replay("", InMemoryEventStore()).passed
    assert not check_replay("   ", InMemoryEventStore()).passed


def test_ttl_covers_whole_acceptance_window():
    # a request stamped W seconds in the future stays acceptable for another W
    assert ttl_for_window(300, 300) >= 600


def test_replay_still_blocked_at_edge_of_window():
    """Event accepted now, replayed just before its timestamp would expire."""
    clock = FakeClock()
    s = InMemoryEventStore(clock=clock)
    assert check_replay("evt_1", s, window_seconds=300, future_skew_seconds=300).passed
    clock.advance(599)   # timestamp (up to +300 ahead) is still inside window here
    assert not check_replay("evt_1", s, window_seconds=300, future_skew_seconds=300).passed


# ---- factory ---------------------------------------------------------------
def test_factory(tmp_path):
    assert isinstance(create_event_store("memory"), InMemoryEventStore)
    s = create_event_store("sqlite", path=str(tmp_path / "f.db"))
    assert isinstance(s, SQLiteEventStore)
    s.close()
    with pytest.raises(ValueError):
        create_event_store("mongo")


# ---- transient SQLite errors (e.g. Windows file locking) --------------------
def test_sqlite_retries_transient_errors(tmp_path, monkeypatch):
    import sqlite3
    s = SQLiteEventStore(path=str(tmp_path / "r.db"))
    real = s._conn()

    class Flaky:
        """Proxy connection: first 2 executes raise 'database is locked'."""
        def __init__(self): self.fails = 2
        def execute(self, *a, **k):
            if self.fails > 0:
                self.fails -= 1
                raise sqlite3.OperationalError("database is locked")
            return real.execute(*a, **k)

    flaky = Flaky()
    monkeypatch.setattr(s, "_conn", lambda: flaky)
    assert s.check_and_set("evt_1", 60) is True          # succeeded after retries
    assert s.check_and_set("evt_1", 60) is False         # and recorded exactly once


def test_sqlite_non_transient_error_fails_fast(tmp_path, monkeypatch):
    import sqlite3
    s = SQLiteEventStore(path=str(tmp_path / "n.db"))

    class Broken:
        def execute(self, *a, **k):
            raise sqlite3.OperationalError("no such table: seen_events")

    monkeypatch.setattr(s, "_conn", lambda: Broken())
    with pytest.raises(StoreUnavailable):
        s.check_and_set("evt_1", 60)
