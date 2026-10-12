
import pytest

from app.config import load_config


def test_default_config(monkeypatch):
    for name in (
        "TIMESTAMP_WINDOW_SECONDS",
        "EVENT_STORE",
        "EVENT_STORE_PATH",
        "SQLITE_PATH",
        "REDIS_URL",
        "LOG_PATH",
    ):
        monkeypatch.delenv(name, raising=False)

    config = load_config()

    assert config.timestamp_window == 300
    assert config.event_store == "sqlite"
    assert config.event_store_path == "data/events.db"
    assert config.sqlite_path == "data/events.db"
    assert config.redis_url == "redis://localhost:6379/0"
    assert config.log_path == "logs/security.jsonl"


def test_custom_timestamp_window(monkeypatch):
    monkeypatch.setenv("TIMESTAMP_WINDOW_SECONDS", "120")

    config = load_config()

    assert config.timestamp_window == 120


def test_invalid_timestamp_window(monkeypatch):
    monkeypatch.setenv("TIMESTAMP_WINDOW_SECONDS", "0")

    with pytest.raises(ValueError):
        load_config()


def test_invalid_store(monkeypatch):
    monkeypatch.setenv("EVENT_STORE", "unknown")

    with pytest.raises(ValueError):
        load_config()


def test_sqlite_path_backward_compatibility(monkeypatch):
    monkeypatch.delenv("EVENT_STORE_PATH", raising=False)
    monkeypatch.setenv("SQLITE_PATH", "./legacy.db")

    config = load_config()

    assert config.event_store_path == "./legacy.db"
    assert config.sqlite_path == "./legacy.db"


def test_event_store_path_takes_precedence(monkeypatch):
    monkeypatch.setenv("SQLITE_PATH", "./legacy.db")
    monkeypatch.setenv("EVENT_STORE_PATH", "./current.db")

    config = load_config()

    assert config.event_store_path == "./current.db"

