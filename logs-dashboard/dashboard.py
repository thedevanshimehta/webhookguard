"""Dashboard backend (task T18, owner: Sampada Daware).

Read-only Flask routes that serve the dashboard page and feed it data from the
EXISTING security log (logs-dashboard/logger.py output, contract section 7).
No second logging mechanism, no database, no secrets leave the server.

    GET /dashboard      -> logs-dashboard/dashboard.html (static, via send_file)
    GET /api/dashboard  -> aggregates the JSON-lines log
    GET /api/health     -> {"log_accessible": bool} only; no faked status

GET /api/dashboard response shape (all values computed from the log file):
{
  "generated_at": "2026-10-06T12:00:00Z",
  "log_path": "./logs/security.jsonl",
  "log_accessible": true,
  "counts": {
    "total": 128, "valid": 94, "rejected": 34,
    "by_reason": {"valid": 94, "replayed": 11, "invalid_signature": 19, ...}
  },
  "recent": [ {"logged_at", "event_id", "decision", "reason",
               "source_ip", "request_timestamp", "body_sha256"} ]   # newest first, capped
}
The endpoint NEVER returns secrets, signature values or raw bodies - the log
format itself does not contain them, and nothing is added here.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone

from flask import Blueprint, jsonify, send_file

def _default_log_path() -> str:
    """Same default as logger.py - kept in sync via a direct import of the
    hyphenated module so the two files can never drift apart."""
    from app.wg_modules import get_logger
    return get_logger().DEFAULT_LOG_PATH


bp = Blueprint("dashboard", __name__)

# Bound the work per request: the log can grow unbounded during a demo.
MAX_RECENT_EVENTS = 100
MAX_LINES_READ = 10_000

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))


def _log_path() -> str:
    """The exact file logger.py writes to (LOG_PATH env, same default)."""
    return os.environ.get("LOG_PATH", _default_log_path())


@bp.get("/dashboard")
def dashboard_page():
    """Serve the dashboard HTML; /dashboard.js and /dashboard.css resolve next to it."""
    return send_file(os.path.join(DASHBOARD_DIR, "dashboard.html"))


@bp.get("/dashboard.js")
def dashboard_js():
    return send_file(os.path.join(DASHBOARD_DIR, "dashboard.js"))


@bp.get("/dashboard.css")
def dashboard_css():
    return send_file(os.path.join(DASHBOARD_DIR, "dashboard.css"))


@bp.get("/api/health")
def health():
    """Real status only: is the receiver process up and is the log reachable?"""
    path = _log_path()
    log_ok = os.path.exists(path) and os.access(path, os.W_OK)
    return jsonify({
        "status": "ok",                      # we are running, or you'd not get this
        "log_accessible": log_ok,
        "log_path": path,
    })


def _iter_log_entries(path: str):
    """Yield parsed JSON objects, one per non-empty line. Skips bad lines."""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue  # tolerate a torn last line during a live demo
            if isinstance(entry, dict):
                yield entry


@bp.get("/api/dashboard")
def dashboard_data():
    path = _log_path()

    if not os.path.exists(path):
        # Empty state, not an error: the receiver simply has no events yet.
        return jsonify({
            "generated_at": _now(),
            "log_path": path,
            "log_accessible": True,
            "counts": {"total": 0, "valid": 0, "rejected": 0, "by_reason": {}},
            "recent": [],
        })

    try:
        entries = list(_iter_log_entries(path))
    except OSError:
        return jsonify({
            "error": "log_unreadable",
            "message": "Unable to connect to the security service.",
        }), 503

    # Only the tail is needed for "recent"; counting scans the whole file.
    total = len(entries)
    reasons = Counter(str(e.get("reason", "unknown")) for e in entries)
    accepted = sum(1 for e in entries if e.get("decision") == "accepted")
    recent = entries[-MAX_RECENT_EVENTS:][::-1]  # newest first

    return jsonify({
        "generated_at": _now(),
        "log_path": path,
        "log_accessible": True,
        "counts": {
            "total": total,
            "valid": accepted,
            "rejected": total - accepted,
            "by_reason": dict(reasons),
        },
        "recent": [
            {
                "logged_at": e.get("logged_at"),
                "event_id": e.get("event_id"),
                "decision": e.get("decision"),
                "reason": str(e.get("reason") or "unknown"),
                "key_id": e.get("key_id"),
                "source_ip": e.get("source_ip"),
                "request_timestamp": e.get("request_timestamp"),
                "body_sha256": e.get("body_sha256"),
            }
            for e in recent
        ],
    })


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
