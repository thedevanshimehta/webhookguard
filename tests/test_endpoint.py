from receiver.pipeline.endpoint import create_webhook_app
from receiver.pipeline.result import Decision


def test_endpoint_passes_raw_body_and_headers_to_verifier():
    captured = {}

    def verifier(headers, body, source_ip):
        captured.update(headers=headers, body=body, source_ip=source_ip)
        return Decision(True, "valid", 200, "evt_12345", "k1")

    client = create_webhook_app(verifier).test_client()
    response = client.post(
        "/webhook",
        data=b'{"amount":500}\n',
        headers={"X-Webhook-Event-Id": "evt_12345"},
        environ_base={"REMOTE_ADDR": "203.0.113.5"},
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "accepted",
        "reason": "valid",
        "event_id": "evt_12345",
    }
    assert captured["body"] == b'{"amount":500}\n'
    assert captured["headers"]["X-Webhook-Event-Id"] == "evt_12345"
    assert captured["source_ip"] == "203.0.113.5"
