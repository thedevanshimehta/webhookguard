
"""T16: demonstrate rejection of a replayed webhook."""

import json

from attacks.common import make_request, payment_body, send_request


def main() -> None:
    body = payment_body(500)
    headers, body = make_request(body)

    print("Sending the same signed webhook twice.")

    first_status, first_body = send_request(
        headers, body, "first-delivery"
    )
    second_status, second_body = send_request(
        headers, body, "replayed-delivery"
    )

    try:
        first_result = json.loads(first_body)
    except json.JSONDecodeError:
        first_result = {}

    try:
        second_result = json.loads(second_body)
    except json.JSONDecodeError:
        second_result = {}

    if (
        first_status == 200
        and first_result.get("reason") == "valid"
        and second_status == 409
        and second_result.get("reason") == "replayed"
    ):
        print("PASS: replay correctly rejected.")
    else:
        print("FAIL: expected 200/valid, followed by 409/replayed.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
