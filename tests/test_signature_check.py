from receiver.pipeline.result import INVALID_SIGNATURE, MALFORMED, UNKNOWN_KEY, VALID
from receiver.pipeline.signature_check import check_signature
from receiver.crypto.hmac_utils import build_canonical, compute_signature


SECRET = b"test-secret"
TIMESTAMP = "1727445520"
EVENT_ID = "evt_12345"
BODY = b'{"event":"payment.success","amount":500,"currency":"INR"}'


def signed_header(timestamp=TIMESTAMP, event_id=EVENT_ID, body=BODY):
    canonical = build_canonical(timestamp, event_id, body)
    return "sha256=" + compute_signature(SECRET, canonical)


def test_valid_signature(monkeypatch):
    monkeypatch.setattr("keys.key_manager.get_key", lambda key_id: SECRET)

    result = check_signature(
        "k1", TIMESTAMP, EVENT_ID, BODY, signed_header()
    )

    assert result.ok is True
    assert result.reason == VALID


def test_tampered_body_is_rejected(monkeypatch):
    monkeypatch.setattr("keys.key_manager.get_key", lambda key_id: SECRET)

    result = check_signature(
        "k1", TIMESTAMP, EVENT_ID, b'{"amount":5000}', signed_header()
    )

    assert result.ok is False
    assert result.reason == INVALID_SIGNATURE


def test_unknown_key_is_rejected_before_hmac(monkeypatch):
    monkeypatch.setattr("keys.key_manager.get_key", lambda key_id: None)

    result = check_signature("retired", TIMESTAMP, EVENT_ID, BODY, signed_header())

    assert result.ok is False
    assert result.reason == UNKNOWN_KEY


def test_signature_header_must_use_lowercase_sha256_hex(monkeypatch):
    monkeypatch.setattr("keys.key_manager.get_key", lambda key_id: SECRET)

    result = check_signature("k1", TIMESTAMP, EVENT_ID, BODY, "SHA256=" + "0" * 64)

    assert result.ok is False
    assert result.reason == MALFORMED
