
# app/config.py

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MAX_BODY_BYTES = 1024 * 1024  # 1 MiB; webhook payloads are small


@dataclass(frozen=True)
class Config:
    timestamp_window: int
    event_store: str
    event_store_path: str
    redis_url: str
    log_path: str
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES

    # Backward compatibility with existing code.
    @property
    def sqlite_path(self):
        return self.event_store_path


def load_env() -> None:
    """Load the project's .env into os.environ (existing variables win).

    Every entry point (receiver, sender CLI, attack scripts) calls this, so a
    key placed in .env works everywhere, not only in the receiver.
    """
    load_dotenv(PROJECT_ROOT / ".env")


def load_config() -> Config:
    # Load variables from the project's .env file.
    load_env()

    try:
        window = int(
            os.getenv("TIMESTAMP_WINDOW_SECONDS", "300")
        )
    except ValueError as exc:
        raise ValueError(
            "TIMESTAMP_WINDOW_SECONDS must be an integer"
        ) from exc

    if window <= 0:
        raise ValueError(
            "TIMESTAMP_WINDOW_SECONDS must be positive"
        )

    event_store = os.getenv(
        "EVENT_STORE", "sqlite"
    ).strip().lower()

    if event_store not in ("sqlite", "redis", "memory"):
        raise ValueError(
            "EVENT_STORE must be sqlite, redis, or memory"
        )

    # Prefer EVENT_STORE_PATH; support the old SQLITE_PATH
    # setting temporarily for backward compatibility.
    event_store_path = os.getenv(
        "EVENT_STORE_PATH",
        os.getenv("SQLITE_PATH", "data/events.db"),
    )

    redis_url = os.getenv(
        "REDIS_URL", "redis://localhost:6379/0"
    )

    log_path = os.getenv(
        "LOG_PATH", "logs/security.jsonl"
    )

    try:
        max_body_bytes = int(
            os.getenv("MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES))
        )
    except ValueError as exc:
        raise ValueError("MAX_BODY_BYTES must be an integer") from exc

    if max_body_bytes <= 0:
        raise ValueError("MAX_BODY_BYTES must be positive")

    if not event_store_path.strip():
        raise ValueError("EVENT_STORE_PATH cannot be empty")

    if not redis_url.strip():
        raise ValueError("REDIS_URL cannot be empty")

    if not log_path.strip():
        raise ValueError("LOG_PATH cannot be empty")

    return Config(
        timestamp_window=window,
        event_store=event_store,
        event_store_path=event_store_path,
        redis_url=redis_url,
        log_path=log_path,
        max_body_bytes=max_body_bytes,
    )

