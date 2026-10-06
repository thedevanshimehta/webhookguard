"""Stress / traffic simulation for replay detection (T13).

Generates N unique fake payment events, adds deliberate duplicates (replays),
shuffles them, fires them through check_replay() - optionally from many threads -
and verifies that EXACTLY the duplicates were rejected.

    python -m tests.stress_replay                          # sqlite, 100k events, 15% dupes
    python -m tests.stress_replay --backend memory
    python -m tests.stress_replay --backend redis --redis-url redis://localhost:6379/0
    python -m tests.stress_replay --events 200000 --dup-ratio 0.2 --threads 16

Exit code 0 = all checks passed, 1 = a check failed.
"""
from __future__ import annotations

import argparse
import logging
import os
import random
import sys
import tempfile
import threading
import time
import uuid
from collections import Counter

from receiver.pipeline.replay_check import check_replay
from store.event_store import create_event_store


def build_traffic(n_unique: int, dup_ratio: float, seed: int):
    rng = random.Random(seed)
    run = uuid.uuid4().hex[:8]                     # keeps IDs unique across runs (matters for Redis)
    ids = [f"evt_{run}_{i:07d}" for i in range(n_unique)]
    n_dups = int(n_unique * dup_ratio)
    # each duplicate is a resend of a random earlier event; some events get replayed several times
    dups = [rng.choice(ids) for _ in range(n_dups)]
    traffic = ids + dups
    rng.shuffle(traffic)
    # expected: first arrival of each ID accepted, every later arrival rejected
    return traffic, len(set(traffic)), len(traffic) - len(set(traffic))


class _ErrCollector(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.msgs = Counter()

    def emit(self, record):
        self.msgs[record.getMessage()] += 1


def run(args) -> int:
    collector = _ErrCollector()
    logging.getLogger("webhookguard.replay").addHandler(collector)
    traffic, expect_ok, expect_replay = build_traffic(args.events, args.dup_ratio, args.seed)
    tmp = tempfile.mkdtemp()
    store = create_event_store(args.backend, path=os.path.join(tmp, "stress.db"),
                               redis_url=args.redis_url)
    print(f"backend={args.backend}  requests={len(traffic):,}  unique={expect_ok:,}  "
          f"deliberate replays={expect_replay:,}  threads={args.threads}")

    counts, lock = Counter(), threading.Lock()
    chunks = [traffic[i::args.threads] for i in range(args.threads)]
    barrier = threading.Barrier(args.threads)

    def worker(chunk):
        local = Counter()
        barrier.wait()
        for evt in chunk:
            r = check_replay(evt, store)
            local[(r.http_status, r.reason)] += 1
        with lock:
            counts.update(local)

    t0 = time.perf_counter()
    threads = [threading.Thread(target=worker, args=(c,)) for c in chunks]
    [t.start() for t in threads]
    [t.join() for t in threads]
    dt = time.perf_counter() - t0
    store.close()

    ok = counts[(200, "valid")]
    replayed = counts[(409, "replayed")]
    other = sum(v for k, v in counts.items() if k not in {(200, "valid"), (409, "replayed")})

    print(f"\naccepted (200 valid)     : {ok:,}   expected {expect_ok:,}")
    print(f"rejected (409 replayed)  : {replayed:,}   expected {expect_replay:,}")
    print(f"other / errors           : {other:,}   expected 0")
    for msg, n in collector.msgs.most_common(5):
        print(f"  error x{n}: {msg}")
    print(f"time {dt:.2f}s  ->  {len(traffic)/dt:,.0f} requests/sec")

    passed = (ok == expect_ok and replayed == expect_replay and other == 0)
    print("\nRESULT:", "PASS - exactly the duplicates were rejected" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--backend", choices=["sqlite", "redis", "memory"], default="sqlite")
    p.add_argument("--events", type=int, default=100_000, help="number of unique events")
    p.add_argument("--dup-ratio", type=float, default=0.15, help="duplicates as fraction of unique events")
    p.add_argument("--threads", type=int, default=8)
    p.add_argument("--redis-url", default="redis://localhost:6379/0")
    p.add_argument("--seed", type=int, default=42)
    sys.exit(run(p.parse_args()))
