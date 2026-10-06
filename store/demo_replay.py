"""Quick manual demo of replay detection (no server needed).

    python -m store.demo_replay                 # SQLite (default)
    python -m store.demo_replay redis           # needs a local Redis on :6379
    python -m store.demo_replay memory
"""
import sys
import tempfile
import os

from receiver.pipeline.replay_check import check_replay
from store.event_store import create_event_store

kind = sys.argv[1] if len(sys.argv) > 1 else "sqlite"
path = os.path.join(tempfile.mkdtemp(), "demo.db")
store = create_event_store(kind, path=path)

print(f"backend: {kind}\n")
for label, evt in [("first delivery of evt_12345", "evt_12345"),
                   ("ATTACKER resends evt_12345", "evt_12345"),
                   ("ATTACKER resends evt_12345 again", "evt_12345"),
                   ("new legitimate event evt_67890", "evt_67890")]:
    r = check_replay(evt, store)
    print(f"{label:38s} -> HTTP {r.http_status}  reason={r.reason}")
store.close()
