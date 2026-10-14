import json
import re
import threading

from receiver.pipeline.result import Decision, VALID, MALFORMED, UNKNOWN_KEY, INVALID_SIGNATURE, HTTP_STATUS
from receiver.pipeline.timestamp_check import check_timestamp
from receiver.pipeline.replay_check import check_replay
from receiver.pipeline.security_log import log_decision
from receiver.pipeline.signature_check import check_signature
from store.event_store import EventStore
from store.event_store import create_event_store
from app.config import Config, load_config

EVENT_ID_REGEX = re.compile(r'^[A-Za-z0-9_-]{8,64}$')
MAX_TIMESTAMP_DIGITS = 15  # Unix seconds have 10 digits until the year 2286

# Reasons that are logged precisely but reported to the client in a less
# revealing form. Answering "unknown_key" would let anyone probe which key IDs
# exist, so the client sees the same answer as for a bad signature.
_PUBLIC_REASON = {UNKNOWN_KEY: INVALID_SIGNATURE}

# Stores created for callers that do not pass one, one per configuration, so
# replay state is shared between calls instead of starting empty every time.
_default_stores: dict[tuple, EventStore] = {}
_default_stores_lock = threading.Lock()


def verify_webhook(
    headers: dict,
    body: bytes,
    source_ip: str,
    event_store: EventStore | None = None,
    config: Config | None = None,
) -> Decision:
    """
    Orchestrates the webhook verification process.
    Section 3: Verification order

    The Flask app passes the event store and config it created at startup.
    Direct callers may omit them; config is then loaded and a shared default
    store for that config is used.
    """
    if config is None:
        config = load_config()
    log_path = config.log_path
    headers = {str(name).lower(): value for name, value in headers.items()}

    # 1. Parse and validate headers and body
    content_type = headers.get('content-type')
    if not content_type or 'application/json' not in content_type:
        return _reject(MALFORMED, None, None, source_ip, None, body, log_path)

    timestamp_str = headers.get('x-webhook-timestamp')
    event_id = headers.get('x-webhook-event-id')
    key_id = headers.get('x-webhook-key-id')
    signature_header = headers.get('x-webhook-signature')

    if not timestamp_str or not event_id or not key_id or not signature_header:
        return _reject(MALFORMED, None, None, source_ip, None, body, log_path)

    # Contract: integer Unix seconds, plain ASCII digits only. int() alone would
    # also accept "+123", " 123", "1_000" and non-ASCII digits. The length cap
    # keeps int() away from huge inputs (it refuses more than 4300 digits).
    if not (timestamp_str.isascii() and timestamp_str.isdigit()
            and len(timestamp_str) <= MAX_TIMESTAMP_DIGITS):
        return _reject(MALFORMED, event_id, key_id, source_ip, None, body, log_path)
    timestamp_int = int(timestamp_str)

    if not EVENT_ID_REGEX.fullmatch(event_id):
        return _reject(MALFORMED, event_id, key_id, source_ip, timestamp_int, body, log_path)

    if not signature_header.startswith('sha256='):
        return _reject(MALFORMED, event_id, key_id, source_ip, timestamp_int, body, log_path)

    # A webhook payload is a JSON object; "123" or "[]" is valid JSON but not an event.
    # RecursionError: deeply nested JSON ("{"a":{"a":...") exhausts the parser's stack.
    try:
        payload = json.loads(body)
    except (ValueError, RecursionError):
        payload = None
    if not isinstance(payload, dict):
        return _reject(MALFORMED, event_id, key_id, source_ip, timestamp_int, body, log_path)

    # 2 & 3. Key lookup and Signature check (handled by check_signature which calls key_manager)
    sig_result = check_signature(key_id, timestamp_str, event_id, body, signature_header)
    if not sig_result.ok:
        return _reject(sig_result.reason, event_id, key_id, source_ip, timestamp_int, body, log_path)

    # 4. Timestamp check
    ts_result = check_timestamp(timestamp_int, window=config.timestamp_window)
    if not ts_result.ok:
        return _reject(ts_result.reason, event_id, key_id, source_ip, timestamp_int, body, log_path)

    # 5. Replay check
    store = event_store if event_store is not None else _default_store(config)

    replay_result = check_replay(
        event_id,
        store,
        window_seconds=config.timestamp_window,
        future_skew_seconds=config.timestamp_window,
        key_id=key_id,
    )

    if not replay_result.ok:
        return _reject(
            replay_result.reason,
            event_id,
            key_id,
            source_ip,
            timestamp_int,
            body,
            log_path,
        )

    # 6. Accept
    decision = Decision(
        accepted=True,
        reason=VALID,
        http_status=HTTP_STATUS[VALID],
        event_id=event_id,
        key_id=key_id
    )
    log_decision(decision, source_ip, timestamp_int, body, log_path)
    return decision


def _default_store(config: Config) -> EventStore:
    key = (config.event_store, config.event_store_path, config.redis_url)
    with _default_stores_lock:
        store = _default_stores.get(key)
        if store is None:
            store = create_event_store(
                kind=config.event_store,
                path=config.event_store_path,
                redis_url=config.redis_url,
            )
            _default_stores[key] = store
        return store


def _reject(reason: str, event_id: str | None, key_id: str | None, source_ip: str,
            request_timestamp: int | None, body: bytes, log_path: str) -> Decision:
    # The log keeps the precise reason; the returned decision carries the public one.
    logged = Decision(
        accepted=False,
        reason=reason,
        http_status=HTTP_STATUS.get(reason, 400),
        event_id=event_id,
        key_id=key_id
    )
    log_decision(logged, source_ip, request_timestamp, body, log_path)
    public_reason = _PUBLIC_REASON.get(reason, reason)
    return Decision(
        accepted=False,
        reason=public_reason,
        http_status=HTTP_STATUS.get(public_reason, 400),
        event_id=event_id,
        key_id=key_id
    )
