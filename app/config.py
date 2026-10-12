
# app/config.py

import os
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass(frozen=True)
class Config:
    timestamp_window: int
    event_store: str
    event_store_path: str
    redis_url: str
    log_path: str

    # Backward compatibility with existing code.
    @property
    def sqlite_path(self):
        return self.event_store_path


def load_config() -> Config:
    # Load variables from the project's .env file.
    load_dotenv()

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
    )

