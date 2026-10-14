"""Regression tests for the issues found in the dev-branch review.

Each test names the issue it covers. They run the real modules through the
Flask test client, with their own key, store and log under tmp_path.
"""

import importlib
import json
import sys
import time
from pathlib import Path

import pytest

import app.config
from app.config import Config
from app.main import create_app, main as run_main
from attacks.common import make_request, payment_body
from keys import key_manager
from receiver.pipeline import decision_engine
from receiver.pipeline.endpoint import create_webhook_app
from receiver.pipeline.replay_check import check_replay, release_replay
from receiver.crypto.hmac_utils import compute_signature
from store.event_store import InMemoryEventStore, SQLiteEventStore


SECRET = "review-secret-value-0123456789abcdef"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBHOOKGUARD_KEYS", f"k1:{SECRET}")
    monkeypatch.setenv("TIMESTAMP_WINDOW_SECONDS", "300")
    monkeypatch.setenv("EVENT_STORE", "sqlite")
    monkeypatch.setenv("EVENT_STORE_PATH", str(tmp_path / "events.db"))
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "security.jsonl"))
    monkeypatch.delenv("MAX_BODY_BYTES", raising=False)
    return tmp_path


def log_reasons(env):
    path = env / "security.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)["reason"] for line in path.read_text(encoding="utf-8").splitlines()]


def signed_raw(timestamp: str, event_id: str, body: bytes) -> dict:
    """Headers signed over exactly these strings, even if they break the contract."""
    canonical = timestamp.encode("utf-8") + b"." + event_id.encode() + b"." + body
    return {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Event-Id": event_id,
        "X-Webhook-Key-Id": "k1",
        "X-Webhook-Signature": "sha256=" + compute_signature(SECRET.encode(), canonical),
    }


# --------------------------------------------------------------------------- #
# Issue 1: configuration is loaded once at startup, not per request
# --------------------------------------------------------------------------- #
def test_config_is_not_reloaded_per_request(env, monkeypatch):
    app_ = create_webhook_app()
    client = app_.test_client()

    def fail():
        raise AssertionError("load_config called during a request")

    monkeypatch.setattr(decision_engine, "load_config", fail)
    monkeypatch.setattr(app.config, "load_config", fail)

    for _ in range(3):
        headers, body = make_request(payment_body(500))
        assert client.post("/webhook", data=body, headers=headers).status_code == 200
    headers["X-Webhook-Signature"] = "sha256=" + "0" * 64
    assert client.post("/webhook", data=body, headers=headers).status_code == 401
    assert log_reasons(env) == ["valid", "valid", "valid", "invalid_signature"]


# --------------------------------------------------------------------------- #
# Issue 2: body must be a JSON object
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("body", [b"123", b"[]", b'"text"', b"null", b"true"])
def test_non_object_json_body_is_malformed(env, body):
    client = create_webhook_app().test_client()
    headers, body = make_request(body)

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 400
    assert response.get_json()["reason"] == "malformed"


# --------------------------------------------------------------------------- #
# Issue 3: timestamp must be plain ASCII digits
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("make_ts", [
    lambda now: f"{now[:4]}_{now[4:]}",   # int() accepts underscores
    lambda now: f"+{now}",                # and a sign
    lambda now: f"{now}²",           # and is not limited to ASCII digits
    lambda now: f"-{now}",
])
def test_non_canonical_timestamp_is_malformed(env, make_ts):
    client = create_webhook_app().test_client()
    body = payment_body(500)
    headers = signed_raw(make_ts(str(int(time.time()))), "evt_timestamp_check", body)

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 400
    assert response.get_json()["reason"] == "malformed"


@pytest.mark.parametrize("timestamp", ["9" * 16, "9" * 5000])
def test_overlong_timestamp_is_malformed_not_a_crash(env, timestamp):
    # int() raises for more than 4300 digits; this must be a 400, not a 500.
    client = create_webhook_app().test_client()
    body = payment_body(500)
    headers = signed_raw(timestamp, "evt_timestamp_long", body)

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 400
    assert response.get_json()["reason"] == "malformed"


def test_deeply_nested_json_is_malformed_not_a_crash(env):
    # Reaches the JSON parser before the signature check, so no key is needed.
    client = create_webhook_app().test_client()
    nested = b'{"a":' * 100_000 + b"1" + b"}" * 100_000
    headers, body = make_request(nested)
    headers["X-Webhook-Signature"] = "sha256=" + "0" * 64

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 400
    assert response.get_json()["reason"] == "malformed"


# --------------------------------------------------------------------------- #
# Issue 4: the logger does not take over the global module name "logger"
# --------------------------------------------------------------------------- #
def test_security_logger_uses_a_unique_module_name():
    from receiver.pipeline import security_log

    assert "webhookguard_security_logger" in sys.modules
    assert sys.modules.get("logger") is not sys.modules["webhookguard_security_logger"]
    reloaded = importlib.reload(security_log)
    assert reloaded.log_decision is sys.modules["webhookguard_security_logger"].log_decision


# --------------------------------------------------------------------------- #
# Issue 7: verify_webhook without a store keeps replay state between calls
# --------------------------------------------------------------------------- #
def test_direct_verify_webhook_without_store_still_detects_replay(env):
    config = Config(
        timestamp_window=300,
        event_store="memory",
        event_store_path=str(env / "unused.db"),
        redis_url="redis://localhost:6379/0",
        log_path=str(env / "security.jsonl"),
    )
    headers, body = make_request(payment_body(500))

    first = decision_engine.verify_webhook(headers, body, "127.0.0.1", config=config)
    second = decision_engine.verify_webhook(headers, body, "127.0.0.1", config=config)

    assert first.reason == "valid"
    assert second.reason == "replayed"


def test_direct_verify_webhook_accepts_lowercase_header_names(env):
    headers, body = make_request(payment_body(500))
    lower = {name.lower(): value for name, value in headers.items()}

    decision = decision_engine.verify_webhook(lower, body, "127.0.0.1",
                                              event_store=InMemoryEventStore())

    assert decision.reason == "valid"


# --------------------------------------------------------------------------- #
# Issue 8: the .env.example placeholder secret is refused
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("secret", [
    "replace-with-a-long-random-secret",
    "change-me-to-a-long-random-string",
    "some-long-random-string",
])
def test_placeholder_secret_is_rejected(monkeypatch, secret):
    monkeypatch.setenv("WEBHOOKGUARD_KEYS", f"k1:{secret}")

    with pytest.raises(key_manager.KeyConfigError) as exc:
        key_manager.get_signing_key()
    assert secret not in str(exc.value)


def test_env_example_value_is_rejected(monkeypatch):
    # PROJECT_ROOT is redirected by conftest.py; .env.example lives in the repo.
    example = (Path(__file__).resolve().parent.parent / ".env.example").read_text(encoding="utf-8")
    line = next(l for l in example.splitlines() if l.startswith("WEBHOOKGUARD_KEYS="))
    monkeypatch.setenv("WEBHOOKGUARD_KEYS", line.split("=", 1)[1])

    with pytest.raises(key_manager.KeyConfigError):
        key_manager.get_signing_key()


def test_receiver_refuses_to_start_with_placeholder_key(monkeypatch, capsys):
    monkeypatch.setenv("WEBHOOKGUARD_KEYS", "k1:replace-with-a-long-random-secret")

    assert run_main() == 1
    assert "placeholder" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Issue 10: sender CLI and attack scripts read .env
# --------------------------------------------------------------------------- #
@pytest.fixture
def dotenv_only(tmp_path, monkeypatch):
    """A project root whose .env holds the key; the key is not in the environment."""
    (tmp_path / ".env").write_text(f"WEBHOOKGUARD_KEYS=k7:{SECRET}\n", encoding="utf-8")
    monkeypatch.setattr(app.config, "PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("WEBHOOKGUARD_KEYS", "placeholder-for-restore")
    monkeypatch.delenv("WEBHOOKGUARD_KEYS")


def test_sender_cli_reads_key_from_dotenv(dotenv_only, monkeypatch):
    import sender.cli
    from sender.sender import WebhookSendError

    used = {}

    def fake_send(payload, url):
        used["key_id"] = key_manager.get_signing_key()[0]
        raise WebhookSendError("offline", "evt_x", "0")

    monkeypatch.setattr(sender.cli, "send_webhook", fake_send)

    assert sender.cli.main(["--url", "http://127.0.0.1:9/webhook"]) == 1
    assert used["key_id"] == "k7"


def test_attack_scripts_read_key_from_dotenv(dotenv_only):
    import attacks.common

    reloaded = importlib.reload(attacks.common)
    headers, _ = reloaded.make_request(payment_body(500))

    assert headers["X-Webhook-Key-Id"] == "k7"


# --------------------------------------------------------------------------- #
# Issue 11: request size limit with a JSON 413 response
# --------------------------------------------------------------------------- #
def test_oversized_body_is_rejected_with_json_413(env, monkeypatch):
    monkeypatch.setenv("MAX_BODY_BYTES", "1024")
    client = create_webhook_app().test_client()
    headers, body = make_request(b'{"x":"' + b"A" * 5000 + b'"}')

    response = client.post("/webhook", data=body, headers=headers)

    assert response.status_code == 413
    assert response.get_json() == {
        "status": "rejected",
        "reason": "too_large",
        "event_id": headers["X-Webhook-Event-Id"],
    }
    assert log_reasons(env) == ["too_large"]


def test_default_body_limit_is_one_mebibyte(env):
    assert create_webhook_app().config["MAX_CONTENT_LENGTH"] == 1024 * 1024


@pytest.mark.parametrize("value", ["0", "-5", "big"])
def test_invalid_max_body_bytes_is_refused(env, monkeypatch, value):
    monkeypatch.setenv("MAX_BODY_BYTES", value)

    with pytest.raises(ValueError):
        app.config.load_config()


# --------------------------------------------------------------------------- #
# Issue 12: a malformed event ID is "malformed", not "replayed"
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("event_id", ["", "   ", None])
def test_replay_check_reports_malformed_event_id(event_id):
    result = check_replay(event_id, InMemoryEventStore())

    assert (result.passed, result.reason, result.http_status) == (False, "malformed", 400)


# --------------------------------------------------------------------------- #
# Issue 17: accepted events reach the application; failures can be retried
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("make_store", [
    lambda tmp: InMemoryEventStore(),
    lambda tmp: SQLiteEventStore(path=str(tmp / "release.db")),
])
def test_store_release_forgets_event(tmp_path, make_store):
    store = make_store(tmp_path)

    assert check_replay("evt_release_1", store, key_id="k1").passed
    assert release_replay("evt_release_1", store, key_id="k1")
    assert check_replay("evt_release_1", store, key_id="k1").passed
    assert not check_replay("evt_release_1", store, key_id="k1").passed
    store.close()


def test_redis_store_release_forgets_event():
    fakeredis = pytest.importorskip("fakeredis")
    from store.event_store import RedisEventStore

    store = RedisEventStore(client=fakeredis.FakeRedis())

    assert check_replay("evt_release_1", store, key_id="k1").passed
    assert release_replay("evt_release_1", store, key_id="k1")
    assert check_replay("evt_release_1", store, key_id="k1").passed
    assert not check_replay("evt_release_1", store, key_id="k1").passed


def test_failed_processing_is_released_so_retry_succeeds(env):
    processed = []
    attempts = {"n": 0}

    def flaky_handler(payload, decision):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("database down")
        processed.append(payload["amount"])

    client = create_webhook_app(handler=flaky_handler).test_client()
    headers, body = make_request(payment_body(500))

    first = client.post("/webhook", data=body, headers=headers)
    retry = client.post("/webhook", data=body, headers=headers)
    replay = client.post("/webhook", data=body, headers=headers)

    assert (first.status_code, first.get_json()["reason"]) == (500, "processing_failed")
    assert (retry.status_code, retry.get_json()["reason"]) == (200, "valid")
    assert (replay.status_code, replay.get_json()["reason"]) == (409, "replayed")
    assert processed == [500]
    assert log_reasons(env) == ["valid", "processing_failed", "valid", "replayed"]


def test_protected_ledger_only_contains_genuine_payments(env):
    client = create_app().test_client()

    genuine_headers, genuine_body = make_request(payment_body(500))
    tampered_headers, _ = make_request(payment_body(500))
    expired_headers, expired_body = make_request(
        payment_body(500), timestamp=int(time.time()) - 400
    )

    client.post("/webhook", data=genuine_body, headers=genuine_headers)       # accepted
    client.post("/webhook", data=genuine_body, headers=genuine_headers)       # replay
    client.post("/webhook", data=payment_body(5000), headers=tampered_headers)  # tampered
    client.post("/webhook", data=expired_body, headers=expired_headers)       # expired

    ledger = client.get("/ledger").get_json()
    assert ledger["count"] == 1
    assert ledger["total_amount"] == 500
    assert ledger["entries"][0]["event_id"] == genuine_headers["X-Webhook-Event-Id"]

    assert client.post("/reset").get_json() == {"status": "reset"}
    assert client.get("/ledger").get_json()["count"] == 0


# --------------------------------------------------------------------------- #
# Issue 16: security dashboard
# --------------------------------------------------------------------------- #
def test_dashboard_page_and_data(env):
    client = create_app().test_client()
    headers, body = make_request(payment_body(500))
    client.post("/webhook", data=body, headers=headers)
    client.post("/webhook", data=body, headers=headers)
    client.post("/webhook", data=payment_body(5000), headers=headers)

    page = client.get("/dashboard")
    data = client.get("/dashboard/data").get_json()

    assert page.status_code == 200
    assert b"WebhookGuard security dashboard" in page.data
    assert data["total"] == 3
    assert data["accepted"] == 1
    assert data["counts"] == {"valid": 1, "replayed": 1, "invalid_signature": 1}
    assert [e["reason"] for e in data["recent"]] == ["invalid_signature", "replayed", "valid"]


def test_dashboard_never_inserts_log_values_as_html():
    from receiver.pipeline.endpoint import DASHBOARD_HTML

    page = open(DASHBOARD_HTML, encoding="utf-8").read()

    assert "innerHTML" not in page
    assert "insertAdjacentHTML" not in page
