"""Keep the developer's real .env out of the test suite.

app.config.load_env() reads PROJECT_ROOT/.env, and it runs on import of
attacks.common as well as on every load_config(). Without this, values in a
local .env (EVENT_STORE_PATH, WEBHOOKGUARD_KEYS, ...) would leak into tests and
override what each test sets up. pytest imports this file before collecting
any test module, so PROJECT_ROOT points at an empty folder from the start.
Tests that need a .env (see test_review_fixes.py) point PROJECT_ROOT at their
own tmp_path with monkeypatch.
"""

import tempfile
from pathlib import Path

import app.config

app.config.PROJECT_ROOT = Path(tempfile.mkdtemp(prefix="webhookguard-tests-"))
