"""Configuration loading (task T04, owner: Devanshi Mehta).

Reads the environment variables frozen in docs/api-contract.md section 9 /
.env.example. load_config() raises KeyConfigError only if WEBHOOKGUARD_KEYS is
missing or malformed (the receiver must not run without a key).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from keys.key_manager import KeyConfigError, _load_keys


@dataclass(frozen=True)
class Config:
    timestamp_window: int
    event_store: str          # "sqlite" | "redis" | "memory"
    sqlite_path: str
    redis_url: str
    log_path: str


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)).strip())
    except ValueError:
        return default


def load_config() -> Config:
    """Load config from the environment. Validates WEBHOOKGUARD_KEYS early."""
    _load_keys()  # fails fast with KeyConfigError if keys are missing/malformed

    return Config(
        timestamp_window=_env_int("TIMESTAMP_WINDOW_SECONDS", 300),
        event_store=os.environ.get("EVENT_STORE", "sqlite").strip().lower() or "sqlite",
        sqlite_path=os.environ.get("SQLITE_PATH", "./webhookguard.db").strip() or "./webhookguard.db",
        redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        log_path=os.environ.get("LOG_PATH", "./logs/security.jsonl").strip() or "./logs/security.jsonl",
    )
