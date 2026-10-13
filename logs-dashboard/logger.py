import json
import os
import threading
from datetime import datetime, timezone
import hashlib

# One write at a time, so lines from concurrent requests never interleave.
_write_lock = threading.Lock()

def log_decision(
    decision,
    source_ip: str,
    request_timestamp: int | None,
    body: bytes,
    log_path: str | None = None,
) -> None:
    """
    Appends one security log entry (JSON Lines) to log_path.
    Format specified in API Contract Section 7.

    The receiver passes log_path from the config it loaded once at startup.
    If it is omitted, LOG_PATH is read from the configuration.
    """
    if log_path is None:
        from app.config import load_config
        log_path = load_config().log_path

    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)

    body_sha256 = None
    if body is not None:
        body_sha256 = hashlib.sha256(body).hexdigest()

    log_entry = {
        "logged_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_id": decision.event_id,
        "key_id": decision.key_id,
        "decision": "accepted" if decision.accepted else "rejected",
        "reason": decision.reason,
        "source_ip": source_ip,
        "request_timestamp": request_timestamp,
        "body_sha256": body_sha256
    }

    with _write_lock:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')


def read_log(log_path: str, limit: int | None = None) -> list[dict]:
    """Return security log entries, oldest first, skipping damaged lines.

    Used by the dashboard. With limit, only the most recent entries are returned.
    """
    if not os.path.exists(log_path):
        return []
    entries = []
    with open(log_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
    if limit is not None:
        entries = entries[-limit:]
    return entries
