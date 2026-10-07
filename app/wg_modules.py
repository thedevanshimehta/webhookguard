"""Import helper for the hyphenated logs-dashboard/ directory.

The task plan and docs/api-contract.md freeze the file names
logs-dashboard/logger.py and logs-dashboard/dashboard.py, but a hyphen is not
valid in a Python package name, so they cannot be imported with a normal
`import` statement. This module loads each file from its real path exactly
once per process, under a fixed module name, and hands the same module object
to every caller (important so logger.py's write lock is shared repo-wide).
"""
from __future__ import annotations

import importlib.util
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DASHBOARD_DIR = os.path.join(_REPO_ROOT, "logs-dashboard")


def _load_once(module_name: str, file_name: str):
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(
        module_name, os.path.join(LOGS_DASHBOARD_DIR, file_name))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def get_logger():
    """The contract's logs-dashboard/logger.py module."""
    return _load_once("webhookguard_logger", "logger.py")


def get_dashboard():
    """The contract's logs-dashboard/dashboard.py module (Flask blueprint inside)."""
    return _load_once("webhookguard_dashboard", "dashboard.py")
