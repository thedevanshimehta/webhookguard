import pytest
from receiver.crypto.hmac_utils import (
    compute_signature,
    verify_signature,
)

def test_signature_generation():
    secret = b"test-secret"
    message = b"hello webhook"

    signature = compute_signature(secret, message)

    assert signature is not None
    assert len(signature) > 0

def test_valid_signature():
    secret = b"test-secret"
    message = b"hello webhook"

    signature = compute_signature(secret, message)

    assert verify_signature(secret, message, signature)

def test_invalid_signature():
    secret = b"test-secret"
    message = b"hello webhook"

    assert not verify_signature(
        secret, message, "invalid-signature"
    )

def test_modified_message():
    secret = b"test-secret"
    message = b"hello webhook"

    signature = compute_signature(secret, message)

    assert not verify_signature(
        secret, b"modified webhook", signature
    )
