import time

import pytest

from receiver.pipeline.timestamp_check import check_timestamp

# Fixed "now" (the contract test-vector timestamp) so tests are deterministic.
NOW = 1727445520


def test_current_timestamp_is_valid():
    result = check_timestamp(NOW, now=NOW)
    assert result.ok is True
    assert result.reason == "valid"


def test_slightly_old_timestamp_is_valid():
    assert check_timestamp(NOW - 60, now=NOW).ok is True


def test_slightly_future_timestamp_is_valid():
    assert check_timestamp(NOW + 60, now=NOW).ok is True


def test_old_boundary_is_accepted():
    # Exactly 300 s old: contract says <= window is accepted.
    assert check_timestamp(NOW - 300, now=NOW).ok is True


def test_just_past_old_boundary_is_expired():
    result = check_timestamp(NOW - 301, now=NOW)
    assert result.ok is False
    assert result.reason == "expired"


def test_future_boundary_is_accepted():
    assert check_timestamp(NOW + 300, now=NOW).ok is True


def test_just_past_future_boundary_is_expired():
    result = check_timestamp(NOW + 301, now=NOW)
    assert result.ok is False
    assert result.reason == "expired"


def test_very_old_timestamp_is_expired():
    result = check_timestamp(NOW - 86400, now=NOW)
    assert result.ok is False
    assert result.reason == "expired"


def test_far_future_timestamp_is_expired():
    result = check_timestamp(NOW + 10**6, now=NOW)
    assert result.ok is False
    assert result.reason == "expired"


def test_zero_timestamp_is_expired():
    assert check_timestamp(0, now=NOW).reason == "expired"


def test_custom_window():
    assert check_timestamp(NOW - 30, now=NOW, window=30).ok is True
    assert check_timestamp(NOW - 31, now=NOW, window=30).ok is False


@pytest.mark.parametrize("bad", ["1727445520", None, 1727445520.5, True, [], {}])
def test_non_integer_timestamp_is_malformed(bad):
    result = check_timestamp(bad, now=NOW)
    assert result.ok is False
    assert result.reason == "malformed"


def test_now_defaults_to_system_clock():
    assert check_timestamp(int(time.time())).ok is True
    assert check_timestamp(int(time.time()) - 3600).reason == "expired"


def test_result_is_immutable():
    result = check_timestamp(NOW, now=NOW)
    with pytest.raises(Exception):
        result.ok = False
