"""Structured JSON logging to standard output.

Bearer tokens, authorization headers, secrets, and submitted snapshots must never
be logged in a form that leaks them. This module provides the JSON sink; callers
are responsible for passing only safe, generic fields.

A dedicated, non-propagating ``picklejack.audit`` logger carries rejection audit
events. Because it owns exactly one handler and does not propagate, a single
``emit_audit_event`` call produces exactly one JSON line regardless of how the
root or server loggers are configured.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

AUDIT_LOGGER_NAME = "picklejack.audit"


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
    """Install JSON stdout handlers on the root and audit loggers (idempotent)."""
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(_json_stdout_handler())
    root.setLevel(logging.INFO)

    audit = logging.getLogger(AUDIT_LOGGER_NAME)
    audit.handlers.clear()
    audit.addHandler(_json_stdout_handler())
    audit.setLevel(logging.INFO)
    # Own handler only: never double-emit through the root logger.
    audit.propagate = False


def emit_audit_event(
    *,
    action: str,
    outcome: str,
    correlation_id: str,
    actor: str,
    tenant: str,
    message: str = "snapshot rejected",
) -> None:
    """Emit exactly one generic structured audit event.

    Only generic, non-sensitive fields are recorded. The raw snapshot, its
    signature, bearer tokens, authorization headers, secrets, and the type
    allowlist are deliberately excluded.
    """
    logging.getLogger(AUDIT_LOGGER_NAME).info(
        message,
        extra={
            "event": {
                "action": action,
                "outcome": outcome,
                "correlation_id": correlation_id,
                "actor": actor,
                "tenant": tenant,
            }
        },
    )
