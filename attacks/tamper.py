
"""T15: alter a signed payment body but retain the original signature."""

from attacks.common import (
    make_request,
    payment_body,
    send_request,
    expect_invalid_signature,
)


def main() -> None:
    original_body = payment_body(500)
    headers, _ = make_request(original_body)

    # Keep the original signature while changing the amount after signing.
    tampered_body = payment_body(5000)

    print("Attack: amount changed from INR 500 to INR 5000")
    print("The signature header is intentionally unchanged.")

    status, response_body = send_request(
        headers, tampered_body, "tampering"
    )

    expect_invalid_signature(
        status, response_body, "Tampering attack"
    )


if __name__ == "__main__":
    main()
