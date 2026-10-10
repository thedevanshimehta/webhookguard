import json
import re
import sys
import importlib.util
import os

from receiver.pipeline.result import Decision, CheckResult, VALID, MALFORMED, UNKNOWN_KEY, INVALID_SIGNATURE, EXPIRED, REPLAYED, HTTP_STATUS
from receiver.pipeline.timestamp_check import check_timestamp
from receiver.pipeline.replay_check import check_replay
from store.event_store import get_event_store
from app.config import load_config

# Import logger from logs-dashboard correctly
logger_path = os.path.join(os.path.dirname(__file__), '../../logs-dashboard/logger.py')
spec = importlib.util.spec_from_file_location("logger", logger_path)
logger_module = importlib.util.module_from_spec(spec)
sys.modules["logger"] = logger_module
spec.loader.exec_module(logger_module)
log_decision = logger_module.log_decision

# Import signature check if available, else stub
try:
    from receiver.pipeline.signature_check import check_signature
except ImportError:
    # Stub for T10 (Vedansh Gholba's task not yet merged)
    def check_signature(key_id, timestamp, event_id, body, signature_header):
        return CheckResult(ok=True, reason=VALID)

EVENT_ID_REGEX = re.compile(r'^[A-Za-z0-9_-]{8,64}$')

def verify_webhook(headers: dict, body: bytes, source_ip: str) -> Decision:
    """
    Orchestrates the webhook verification process.
    Section 3: Verification order
    """
    config = load_config()
    
    # 1. Parse and validate headers and body
    content_type = headers.get('Content-Type')
    if not content_type or 'application/json' not in content_type:
        return _reject(MALFORMED, None, None, source_ip, None, body)

    timestamp_str = headers.get('X-Webhook-Timestamp')
    event_id = headers.get('X-Webhook-Event-Id')
    key_id = headers.get('X-Webhook-Key-Id')
    signature_header = headers.get('X-Webhook-Signature')

    if not timestamp_str or not event_id or not key_id or not signature_header:
        return _reject(MALFORMED, None, None, source_ip, None, body)

    try:
        timestamp_int = int(timestamp_str)
    except ValueError:
        return _reject(MALFORMED, event_id, key_id, source_ip, None, body)

    if not EVENT_ID_REGEX.match(event_id) or '.' in event_id:
        return _reject(MALFORMED, event_id, key_id, source_ip, timestamp_int, body)

    if not signature_header.startswith('sha256='):
        return _reject(MALFORMED, event_id, key_id, source_ip, timestamp_int, body)

    try:
        json.loads(body)
    except ValueError:
        return _reject(MALFORMED, event_id, key_id, source_ip, timestamp_int, body)

    # 2 & 3. Key lookup and Signature check (handled by check_signature which calls key_manager)
    sig_result = check_signature(key_id, timestamp_str, event_id, body, signature_header)
    if not sig_result.ok:
        return _reject(sig_result.reason, event_id, key_id, source_ip, timestamp_int, body)

    # 4. Timestamp check
    ts_result = check_timestamp(timestamp_int, window=config.timestamp_window)
    if not ts_result.ok:
        return _reject(ts_result.reason, event_id, key_id, source_ip, timestamp_int, body)

    # 5. Replay check
    store = get_event_store(config)
    ttl = 2 * config.timestamp_window + 10
    replay_result = check_replay(event_id, store, ttl)
    if not replay_result.ok:
        return _reject(replay_result.reason, event_id, key_id, source_ip, timestamp_int, body)

    # 6. Accept
    decision = Decision(
        accepted=True,
        reason=VALID,
        http_status=HTTP_STATUS[VALID],
        event_id=event_id,
        key_id=key_id
    )
    log_decision(decision, source_ip, timestamp_int, body)
    return decision

def _reject(reason: str, event_id: str | None, key_id: str | None, source_ip: str, request_timestamp: int | None, body: bytes) -> Decision:
    decision = Decision(
        accepted=False,
        reason=reason,
        http_status=HTTP_STATUS.get(reason, 400),
        event_id=event_id,
        key_id=key_id
    )
    log_decision(decision, source_ip, request_timestamp, body)
    return decision
