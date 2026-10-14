"""End-to-end integration tests (T05, Devanshi Mehta).

Every test runs the real modules together, with no test doubles:

    sender / attack helpers -> Flask endpoint -> decision engine
        -> key manager -> HMAC -> timestamp -> replay (SQLite) -> security log

Requests go through the Flask test client, so no network port is needed. Each
test gets its own key, SQLite database and log file under pytest's tmp_path.
"""

import hashlib
import hmac
import json
import threading
import time

import pytest

from attacks.common import make_request, new_event_id, payment_body
from receiver.crypto.hmac_utils import build_canonical
from receiver.pipeline.endpoint import create_webhook_app
from sender.sender import create_signed_webhook


SECRET = "e2e-secret-value-0123456789abcdef"
OLD_SECRET = "e2e-old-secret-value-fedcba987654"
WINDOW = 300


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Configure the whole stack through environment variables, like a real run."""
    monkeypatch.setenv("WEBHOOKGUARD_KEYS", f"k1:{SECRET}")
    monkeypatch.setenv("TIMESTAMP_WINDOW_SECONDS", str(WINDOW))
    monkeypatch.setenv("EVENT_STORE", "sqlite")
    monkeypatch.setenv("EVENT_STORE_PATH", str(tmp_path / "events.db"))
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "security.jsonl"))
    return tmp_path


@pytest.fixture
def app(env):
    application = create_webhook_app()
    yield application
    application.extensions["webhookguard_event_store"].close()


@pytest.fixture
def client(app):
    return app.test_client()


def post(client, headers, body):
    response = client.post("/webhook", data=body, headers=headers)
    return response.status_code, response.get_json()


def read_log(env):
    path = env / "security.jsonl"
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


# --------------------------------------------------------------------------- #
# Control: genuine traffic is accepted
# --------------------------------------------------------------------------- #
def test_webhook_from_real_sender_is_accepted(client):
    signed = create_signed_webhook(
        {"event": "payment.success", "amount": 500, "currency": "INR"}
    )

    status, data = post(client, signed.headers, signed.body)

    assert status == 200
    assert data == {
        "status": "accepted",
        "reason": "valid",
        "event_id": signed.event_id,
    }


def test_many_distinct_events_are_all_accepted(client):
    for amount in range(1, 21):
        signed = create_signed_webhook({"event": "payment.success", "amount": amount})
        assert post(client, signed.headers, signed.body)[0] == 200


# --------------------------------------------------------------------------- #
# The four attacks from the problem statement
# --------------------------------------------------------------------------- #
def test_forgery_with_wrong_secret_is_rejected(client):
    timestamp = str(int(time.time()))
    event_id = new_event_id()
    body = payment_body(500)
    canonical = build_canonical(timestamp, event_id, body)
    forged = hmac.new(b"attacker-controlled-wrong-secret", canonical, hashlib.sha256)
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Event-Id": event_id,
        "X-Webhook-Key-Id": "k1",
        "X-Webhook-Signature": "sha256=" + forged.hexdigest(),
    }

    status, data = post(client, headers, body)

    assert status == 401
    assert data["reason"] == "invalid_signature"


def test_tampered_amount_is_rejected(client):
    headers, _ = make_request(payment_body(500))

    status, data = post(client, headers, payment_body(5000))

    assert status == 401
    assert data["reason"] == "invalid_signature"


@pytest.mark.parametrize(
    "field", ["X-Webhook-Timestamp", "X-Webhook-Event-Id"]
)
def test_changing_signed_header_is_rejected(client, field):
    headers, body = make_request(payment_body(500))
    if field == "X-Webhook-Timestamp":
        headers[field] = str(int(headers[field]) - 1)
    else:
        headers[field] = new_event_id()

    status, data = post(client, headers, body)

    assert status == 401
    assert data["reason"] == "invalid_signature"


def test_replay_is_rejected(client):
    headers, body = make_request(payment_body(500))

    first = post(client, headers, body)
    second = post(client, headers, body)
    third = post(client, headers, body)

    assert first[0] == 200 and first[1]["reason"] == "valid"
    assert second[0] == 409 and second[1]["reason"] == "replayed"
    assert third[0] == 409 and third[1]["reason"] == "replayed"


def test_expired_request_is_rejected(client):
    headers, body = make_request(
        payment_body(500), timestamp=int(time.time()) - WINDOW - 60
    )

    status, data = post(client, headers, body)

    assert status == 400
    assert data["reason"] == "expired"


def test_far_future_request_is_rejected(client):
    headers, body = make_request(
        payment_body(500), timestamp=int(time.time()) + WINDOW + 60
    )

    status, data = post(client, headers, body)

    assert status == 400
    assert data["reason"] == "expired"


# --------------------------------------------------------------------------- #
# Check ordering: only authenticated, fresh requests may touch the store
# --------------------------------------------------------------------------- #
def test_rejected_requests_do_not_burn_the_event_id(client):
    headers, body = make_request(payment_body(500))

    tampered = post(client, headers, payment_body(5000))
    stale_headers, _ = make_request(
        body, timestamp=int(time.time()) - WINDOW - 60,
        event_id=headers["X-Webhook-Event-Id"],
    )
    stale = post(client, stale_headers, body)
    genuine = post(client, headers, body)

    assert tampered[1]["reason"] == "invalid_signature"
    assert stale[1]["reason"] == "expired"
    assert genuine[0] == 200


def test_replayed_event_with_new_body_is_still_rejected(client):
    event_id = new_event_id()
    first_headers, first_body = make_request(payment_body(500), event_id=event_id)
    second_headers, second_body = make_request(payment_body(700), event_id=event_id)

    assert post(client, first_headers, first_body)[0] == 200
    status, data = post(client, second_headers, second_body)

    assert status == 409
    assert data["reason"] == "replayed"


# --------------------------------------------------------------------------- #
# Key management integration
# --------------------------------------------------------------------------- #
def test_unknown_key_id_is_rejected_without_revealing_it(client, env):
    headers, body = make_request(payment_body(500))
    headers["X-Webhook-Key-Id"] = "k9"

    status, data = post(client, headers, body)

    # The client cannot tell an unknown key ID from a bad signature...
    assert status == 401
    assert data["reason"] == "invalid_signature"
    # ...but the security log keeps the precise reason.
    assert read_log(env)[-1]["reason"] == "unknown_key"


def test_key_rotation_overlap_and_retirement(env, monkeypatch):
    # Before rotation the sender signs with k1.
    monkeypatch.setenv("WEBHOOKGUARD_KEYS", f"k1:{OLD_SECRET}")
    old_headers, old_body = make_request(payment_body(500))
    in_flight_headers, in_flight_body = make_request(payment_body(600))

    # Overlap: k2 is the new signing key, k1 is still accepted.
    monkeypatch.setenv("WEBHOOKGUARD_KEYS", f"k2:{SECRET},k1:{OLD_SECRET}")
    app = create_webhook_app()
    client = app.test_client()
    new_headers, new_body = make_request(payment_body(700))

    assert new_headers["X-Webhook-Key-Id"] == "k2"
    assert post(client, new_headers, new_body)[0] == 200
    assert post(client, old_headers, old_body)[0] == 200

    # Retirement: k1 is removed and its signatures stop working.
    monkeypatch.setenv("WEBHOOKGUARD_KEYS", f"k2:{SECRET}")
    status, data = post(client, in_flight_headers, in_flight_body)

    assert status == 401
    assert data["reason"] == "invalid_signature"
    assert read_log(env)[-1]["reason"] == "unknown_key"
    app.extensions["webhookguard_event_store"].close()


# --------------------------------------------------------------------------- #
# Malformed input
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "missing",
    [
        "X-Webhook-Timestamp",
        "X-Webhook-Event-Id",
        "X-Webhook-Key-Id",
        "X-Webhook-Signature",
    ],
)
def test_missing_security_header_is_malformed(client, missing):
    headers, body = make_request(payment_body(500))
    del headers[missing]

    status, data = post(client, headers, body)

    assert status == 400
    assert data["reason"] == "malformed"


def test_wrong_content_type_is_malformed(client):
    headers, body = make_request(payment_body(500))
    headers["Content-Type"] = "text/plain"

    assert post(client, headers, body) == (
        400,
        {"status": "rejected", "reason": "malformed",
         "event_id": None},
    )


def test_invalid_json_body_is_malformed(client):
    headers, body = make_request(b"{not json")

    status, data = post(client, headers, body)

    assert status == 400
    assert data["reason"] == "malformed"


# --------------------------------------------------------------------------- #
# Persistence and concurrency of replay protection
# --------------------------------------------------------------------------- #
def test_replay_protection_survives_receiver_restart(env):
    headers, body = make_request(payment_body(500))

    first_app = create_webhook_app()
    assert post(first_app.test_client(), headers, body)[0] == 200
    first_app.extensions["webhookguard_event_store"].close()

    restarted_app = create_webhook_app()
    status, data = post(restarted_app.test_client(), headers, body)
    restarted_app.extensions["webhookguard_event_store"].close()

    assert status == 409
    assert data["reason"] == "replayed"


def test_concurrent_duplicate_deliveries_accept_exactly_one(app):
    headers, body = make_request(payment_body(500))
    statuses = []
    lock = threading.Lock()
    start = threading.Barrier(16)

    def deliver():
        client = app.test_client()
        start.wait()
        status, _ = post(client, headers, body)
        with lock:
            statuses.append(status)

    threads = [threading.Thread(target=deliver) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert statuses.count(200) == 1
    assert statuses.count(409) == 15


# --------------------------------------------------------------------------- #
# Security log
# --------------------------------------------------------------------------- #
def test_every_decision_is_logged_with_its_reason(client, env):
    valid_headers, valid_body = make_request(payment_body(500))
    expired_headers, expired_body = make_request(
        payment_body(500), timestamp=int(time.time()) - WINDOW - 60
    )

    post(client, valid_headers, valid_body)                 # valid
    post(client, valid_headers, valid_body)                 # replayed
    post(client, valid_headers, payment_body(5000))         # invalid_signature
    post(client, expired_headers, expired_body)             # expired

    entries = read_log(env)

    assert [e["reason"] for e in entries] == [
        "valid", "replayed", "invalid_signature", "expired"
    ]
    assert [e["decision"] for e in entries] == [
        "accepted", "rejected", "rejected", "rejected"
    ]
    assert entries[0]["event_id"] == valid_headers["X-Webhook-Event-Id"]
    assert entries[0]["key_id"] == "k1"
    assert entries[0]["request_timestamp"] == int(valid_headers["X-Webhook-Timestamp"])
    assert entries[0]["body_sha256"] == hashlib.sha256(valid_body).hexdigest()


def test_log_never_contains_secret_signature_or_raw_body(client, env):
    headers, body = make_request(payment_body(500))
    post(client, headers, body)
    post(client, headers, payment_body(5000))

    raw_log = (env / "security.jsonl").read_text(encoding="utf-8")
    signature_hex = headers["X-Webhook-Signature"].removeprefix("sha256=")

    assert SECRET not in raw_log
    assert signature_hex not in raw_log
    assert body.decode() not in raw_log
    assert "payment.success" not in raw_log
