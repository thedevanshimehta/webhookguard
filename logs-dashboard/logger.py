import json
import os
from datetime import datetime, timezone
import hashlib

def log_decision(decision, source_ip: str, request_timestamp: int | None, body: bytes) -> None:
    """
    Appends one security log entry (JSON Lines) to the file specified in LOG_PATH.
    Format specified in API Contract Section 7.
    """
    from app.config import load_config
    config = load_config()
    log_path = config.log_path

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

    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry) + '\n')
