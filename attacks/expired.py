
"""T16: demonstrate rejection of an expired, correctly signed webhook."""

import json
import os
import time

from attacks.common import make_request, payment_body, send_request


def main() -> None:
    window = int(os.getenv("TIMESTAMP_WINDOW_SECONDS", "300"))
    old_timestamp = int(time.time()) - window - 60

    body = payment_body(500)
    headers, body = make_request(body, timestamp=old_timestamp)

    print(f"Sending a correctly signed request with a timestamp older than {window} seconds.")

    status, response_body = send_request(
        headers, body, "expired-request"
    )

    try:
        result = json.loads(response_body)
    except json.JSONDecodeError:
        result = {}

    if status == 400 and result.get("reason") == "expired":
        print("PASS: expired request rejected.")
    else:
        print(
            "FAIL: expected HTTP 400 / expired, "
            f"received HTTP {status} / {result.get('reason')!r}."
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
