import pytest

from keys import key_manager as km

OLD = "old-secret-value-1234"
NEW = "new-secret-value-5678"


@pytest.fixture
def set_keys(monkeypatch):
    def _set(value):
        if value is None:
            monkeypatch.delenv(km.ENV_VAR, raising=False)
        else:
            monkeypatch.setenv(km.ENV_VAR, value)
    return _set


def test_single_key(set_keys):
    set_keys(f"k1:{OLD}")
    assert km.get_key("k1") == OLD.encode()
    assert km.get_signing_key() == ("k1", OLD.encode())
    assert km.get_active_keys() == {"k1": OLD.encode()}


def test_unknown_key_returns_none(set_keys):
    set_keys(f"k1:{OLD}")
    assert km.get_key("nope") is None


def test_first_key_is_signing_key(set_keys):
    set_keys(f"k2:{NEW},k1:{OLD}")
    assert km.get_signing_key() == ("k2", NEW.encode())


def test_rotation_overlap_accepts_both(set_keys):
    set_keys(f"k2:{NEW},k1:{OLD}")
    active = km.get_active_keys()
    assert set(active) == {"k1", "k2"}
    assert km.get_key("k1") == OLD.encode()  # old key still verifies during overlap


def test_rotation_complete_retires_old_key(set_keys):
    set_keys(f"k2:{NEW}")
    assert km.get_key("k1") is None
    assert set(km.get_active_keys()) == {"k2"}


def test_secret_may_contain_colon(set_keys):
    set_keys("k1:abc:def:ghi12345")
    assert km.get_key("k1") == b"abc:def:ghi12345"


def test_whitespace_is_tolerated(set_keys):
    set_keys(f" k2:{NEW} , k1:{OLD} ")
    assert km.get_signing_key()[0] == "k2"


@pytest.mark.parametrize("bad", [None, "", "   ", "k1", "k1:short", "bad id:longenoughsecret", f"k1:{OLD},k1:{NEW}"])
def test_bad_config_raises(set_keys, bad):
    set_keys(bad)
    with pytest.raises(km.KeyConfigError):
        km.get_active_keys()


def test_errors_do_not_leak_secrets(set_keys):
    set_keys(f"k1:{OLD},k1:{NEW}")
    with pytest.raises(km.KeyConfigError) as exc:
        km.get_active_keys()
    assert OLD not in str(exc.value) and NEW not in str(exc.value)


def test_generate_secret_is_random_and_long():
    a, b = km.generate_secret(), km.generate_secret()
    assert a != b and len(a) == 64