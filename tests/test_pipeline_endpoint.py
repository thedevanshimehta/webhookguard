
import time

import pytest

from receiver.crypto.hmac_utils import build_canonical, compute_signature
from receiver.pipeline.endpoint import create_webhook_app
from store.event_store import StoreUnavailable


TEST_KEY_ID = "testkey"
TEST_SECRET = b"test-secret-for-tests-123456"
TEST_BODY = b'{"event":"payment.success","amount":500}'


@pytest.fixture
def test_environment(tmp_path, monkeypatch):
    """Keep test keys, replay data, and logs separate from normal project data."""
    monkeypatch.setenv(
        "WEBHOOKGUARD_KEYS",
        f"{TEST_KEY_ID}:{TEST_SECRET.decode()}",
    )
    monkeypatch.setenv("TIMESTAMP_WINDOW_SECONDS", "300")
    monkeypatch.setenv("EVENT_STORE", "sqlite")
    monkeypatch.setenv("EVENT_STORE_PATH", str(tmp_path / "events.db"))
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "security.jsonl"))


def make_signed_headers(event_id):
    timestamp = str(int(time.time()))
    canonical = build_canonical(timestamp, event_id, TEST_BODY)
    signature = compute_signature(TEST_SECRET, canonical)

    return {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Event-Id": event_id,
        "X-Webhook-Key-Id": TEST_KEY_ID,
        "X-Webhook-Signature": f"sha256={signature}",
    }


def test_valid_webhook_then_replay(test_environment):
    app = create_webhook_app()
    client = app.test_client()
    headers = make_signed_headers("evt_pipeline_001")

    first = client.post("/webhook", data=TEST_BODY, headers=headers)
    second = client.post("/webhook", data=TEST_BODY, headers=headers)

    assert first.status_code == 200
    assert first.get_json()["reason"] == "valid"

    assert second.status_code == 409
    assert second.get_json()["reason"] == "replayed"


def test_invalid_signature_does_not_consume_event_id(test_environment):
    app = create_webhook_app()
    client = app.test_client()
    headers = make_signed_headers("evt_pipeline_002")

    headers["X-Webhook-Signature"] = "sha256=" + ("0" * 64)

    forged = client.post("/webhook", data=TEST_BODY, headers=headers)
    assert forged.status_code == 401
    assert forged.get_json()["reason"] == "invalid_signature"

    # The same event ID must still work with its genuine signature.
    valid_headers = make_signed_headers("evt_pipeline_002")
    accepted = client.post(
        "/webhook",
        data=TEST_BODY,
        headers=valid_headers,
    )

    assert accepted.status_code == 200
    assert accepted.get_json()["reason"] == "valid"


def test_store_failure_returns_503(test_environment, monkeypatch):
    import store.event_store

    class FailingStore:
        def check_and_set(self, event_id, ttl_seconds):
            raise StoreUnavailable("simulated test failure")

    monkeypatch.setattr(
        store.event_store,
        "create_event_store",
        lambda **kwargs: FailingStore(),
    )

    app = create_webhook_app()
    client = app.test_client()

    response = client.post(
        "/webhook",
        data=TEST_BODY,
        headers=make_signed_headers("evt_pipeline_003"),
    )

    assert response.status_code == 503
    assert response.get_json()["reason"] == "store_unavailable"


def test_app_creates_store_only_once(test_environment, monkeypatch):
    import store.event_store

    real_factory = store.event_store.create_event_store
    created_stores = []

    def counting_factory(**kwargs):
        store = real_factory(**kwargs)
        created_stores.append(store)
        return store

    monkeypatch.setattr(
        store.event_store,
        "create_event_store",
        counting_factory,
    )

    app = create_webhook_app()
    client = app.test_client()

    first = client.post(
        "/webhook",
        data=TEST_BODY,
        headers=make_signed_headers("evt_pipeline_004"),
    )
    second = client.post(
        "/webhook",
        data=TEST_BODY,
        headers=make_signed_headers("evt_pipeline_005"),
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(created_stores) == 1
    assert (
        app.extensions["webhookguard_event_store"]
        is created_stores[0]
    )
