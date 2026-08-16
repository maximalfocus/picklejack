"""Structured JSON logging to standard output.

Bearer tokens, authorization headers, secrets, and submitted snapshots must never
be logged in a form that leaks them. This module provides the JSON sink; callers
are responsible for passing only safe, generic fields.

The rejection audit event (a dedicated, non-propagating ``picklejack.audit``
logger) is added with the defence-in-depth import path in a follow-up issue.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any


class JsonFormatter(logging.Formatter):
    """Render each record as a single compact JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        event = getattr(record, "event", None)
        if isinstance(event, dict):
            payload.update(event)
        return json.dumps(payload, sort_keys=True)


def _json_stdout_handler() -> logging.StreamHandler[Any]:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    return handler


def configure_logging() -> None:
    """Install a JSON stdout handler on the root logger (idempotent)."""
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(_json_stdout_handler())
    root.setLevel(logging.INFO)
