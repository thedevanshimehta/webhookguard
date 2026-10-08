"""Integration coverage for the crypto and replay portions of the receiver.

The endpoint, sender, timestamp checker, and decision engine are not present in
this repository snapshot yet. These tests therefore exercise the real modules
that are available without replacing those future components with test doubles.
"""

import time

import pytest

from receiver.crypto.hmac_utils import (
    build_canonical,
    compute_signature,
    verify_signature,
)
from receiver.pipeline.replay_check import check_replay
from store.event_store import InMemoryEventStore


SECRET = b"test-secret"
BODY = b'{"event":"payment.success","amount":500,"currency":"INR"}'


def _signed(timestamp: str, event_id: str, body: bytes) -> tuple[bytes, str]:
    canonical = build_canonical(timestamp, event_id, body)
    return canonical, compute_signature(SECRET, canonical)


def test_documented_signing_vector():
    canonical, signature = _signed("1727445520", "evt_12345", BODY)

    assert canonical == (
        b'1727445520.evt_12345.'
        b'{"event":"payment.success","amount":500,"currency":"INR"}'
    )
    assert signature == (
        "ab0d1dd6b5aa74d4b082edd7a61a2d42e09e36173303fcccf2657f47a3265f2a"
    )


def test_valid_webhook_is_authenticated_and_accepted_by_replay_step():
    canonical, signature = _signed(str(int(time.time())), "evt_valid_1", BODY)

    assert verify_signature(SECRET, canonical, signature)
    result = check_replay("evt_valid_1", InMemoryEventStore())
    assert result.passed


@pytest.mark.parametrize(
    ("timestamp", "event_id", "body"),
    [
        ("1727445520", "evt_tamper1", b'{"amount":501}'),
        ("1727445521", "evt_tamper1", BODY),
        ("1727445520", "evt_tamper2", BODY),
    ],
)
def test_changes_to_signed_fields_invalidate_signature(timestamp, event_id, body):
    original, signature = _signed("1727445520", "evt_original", BODY)

    changed = build_canonical(timestamp, event_id, body)
    assert original != changed
    assert not verify_signature(SECRET, changed, signature)


def test_forged_signature_is_rejected():
    canonical, _ = _signed("1727445520", "evt_forged1", BODY)

    assert not verify_signature(SECRET, canonical, "0" * 64)


def test_replay_is_rejected_after_first_authenticated_event():
    event_id = "evt_replay1"
    canonical, signature = _signed(str(int(time.time())), event_id, BODY)
    store = InMemoryEventStore()

    assert verify_signature(SECRET, canonical, signature)
    assert check_replay(event_id, store).passed
    assert not check_replay(event_id, store).passed


def test_different_valid_event_ids_are_independent():
    store = InMemoryEventStore()
    for event_id in ("evt_event1", "evt_event2", "evt_event3"):
        canonical, signature = _signed(str(int(time.time())), event_id, BODY)
        assert verify_signature(SECRET, canonical, signature)
        assert check_replay(event_id, store).passed
