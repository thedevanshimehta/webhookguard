"""Security logging (task T14, owner: Harsh Ghole).

Writes one JSON object per line to LOG_PATH, exactly as frozen in
docs/api-contract.md section 7:

    {"logged_at": "2026-10-05T10:15:30Z", "event_id": "evt_12345",
     "key_id": "k1", "decision": "rejected", "reason": "replayed",
     "source_ip": "203.0.113.5", "request_timestamp": 1727445520,
     "body_sha256": "d1119b9d..."}

Rules from the contract:
  * decision: "accepted" | "rejected"; reason: one of the section 4 codes.
  * Missing values (e.g. event_id on a malformed request) are null.
  * NEVER log secrets, full signatures, or the raw body. The body is reduced
    to its SHA-256 hash only.

Logging must never break the webhook response: a log write failure is
reported to stderr, not raised to the caller.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from datetime import datetime, timezone

from receiver.pipeline.result import Decision

# Default matches .env.example; app/config.py passes the configured value in.
DEFAULT_LOG_PATH = "./logs/security.jsonl"

_write_lock = threading.Lock()  # one JSON object per line, even from many threads


def log_decision(decision: Decision,
                 source_ip: str,
                 request_timestamp: int | None,
                 body: bytes | None = None,
                 log_path: str | None = None) -> None:
    """Append one JSON-lines entry for `decision`. Never raises to the caller."""
    path = log_path or os.environ.get("LOG_PATH", DEFAULT_LOG_PATH)

    # Contract: never store the raw body - only its hash. The hash is useful to
    # prove two requests had identical bytes without revealing the content.
    body_sha256 = hashlib.sha256(body).hexdigest() if body is not None else None

    entry = {
        "logged_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_id": decision.event_id,
        "key_id": decision.key_id,
        "decision": "accepted" if decision.accepted else "rejected",
        "reason": decision.reason,
        "source_ip": source_ip or None,
        "request_timestamp": request_timestamp,
        "body_sha256": body_sha256,
    }

    try:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        with _write_lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError as e:
        # Fail soft: the webhook decision is already made; logging is observability.
        print(f"[logger] warning: could not write security log to {path}: {e}",
              file=sys.stderr)
