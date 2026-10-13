import json

import pytest

from app.vulnerable_receiver import HOST, create_app

BODY = b'{"event":"payment.success","amount":500,"currency":"INR","order_id":"ord_1"}'


@pytest.fixture
def client():
    return create_app().test_client()


def post(client, body=BODY, headers=None):
    return client.post(
        "/webhook",
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
    )


def test_accepts_request_with_no_security_headers(client):
    # Forgery: attacker has no secret and sends no signature at all.
    resp = post(client)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "accepted"


def test_accepts_garbage_signature(client):
    resp = post(client, headers={"X-Webhook-Signature": "sha256=" + "0" * 64})
    assert resp.status_code == 200


def test_accepts_tampered_body(client):
    # Tampering: amount changed from 500 to 5000, signature (now wrong) ignored.
    tampered = BODY.replace(b'"amount":500', b'"amount":5000')
    resp = post(client, body=tampered, headers={"X-Webhook-Signature": "sha256=" + "ab" * 32})
    assert resp.status_code == 200
    assert client.get("/ledger").get_json()["entries"][0]["amount"] == 5000


def test_accepts_expired_timestamp(client):
    resp = post(client, headers={"X-Webhook-Timestamp": "1000000000"})
    assert resp.status_code == 200


def test_accepts_replay_and_acts_on_it_twice(client):
    headers = {"X-Webhook-Event-Id": "evt_replayme1"}
    assert post(client, headers=headers).status_code == 200
    assert post(client, headers=headers).status_code == 200
    ledger = client.get("/ledger").get_json()
    assert ledger["count"] == 2
    assert ledger["total_amount"] == 1000  # double credit


def test_response_shape_matches_contract(client):
    resp = post(client, headers={"X-Webhook-Event-Id": "evt_abcdefgh"})
    assert resp.get_json() == {
        "status": "accepted",
        "reason": "valid",
        "event_id": "evt_abcdefgh",
    }


def test_non_json_body_is_malformed(client):
    resp = post(client, body=b"not json")
    assert resp.status_code == 400
    assert resp.get_json()["reason"] == "malformed"


def test_json_array_body_is_malformed(client):
    assert post(client, body=json.dumps([1, 2]).encode()).status_code == 400


def test_ledger_and_reset(client):
    post(client)
    assert client.get("/ledger").get_json()["count"] == 1
    assert client.post("/reset").status_code == 200
    assert client.get("/ledger").get_json()["count"] == 0


def test_each_app_has_its_own_ledger():
    a, b = create_app().test_client(), create_app().test_client()
    post(a)
    assert b.get("/ledger").get_json()["count"] == 0


def test_binds_to_loopback_only():
    assert HOST == "127.0.0.1"
