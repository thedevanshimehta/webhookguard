"""Single import point for the security logger in logs-dashboard/logger.py.

The folder name contains a hyphen, so it cannot be imported as a package. The
file is loaded once under a unique module name; later imports reuse it from
sys.modules instead of executing it again, and nothing else named "logger"
can collide with it.
"""

import importlib.util
import os
import sys

_MODULE_NAME = "webhookguard_security_logger"
_LOGGER_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "logs-dashboard", "logger.py"
)


def _load():
    module = sys.modules.get(_MODULE_NAME)
    if module is None:
        spec = importlib.util.spec_from_file_location(_MODULE_NAME, os.path.normpath(_LOGGER_PATH))
        module = importlib.util.module_from_spec(spec)
        sys.modules[_MODULE_NAME] = module
        spec.loader.exec_module(module)
    return module


_logger = _load()
log_decision = _logger.log_decision
read_log = _logger.read_log

__all__ = ["log_decision", "read_log"]
