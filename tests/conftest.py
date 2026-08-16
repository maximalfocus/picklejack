"""Shared test fixtures."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from picklejack.apps.secure import create_secure_app
from picklejack.apps.vulnerable import create_vulnerable_app
from picklejack.logging_setup import AUDIT_LOGGER_NAME, JsonFormatter

GLOBEX_TOKEN = "demo-token-globex-mallory"
INITECH_TOKEN = "demo-token-initech-peter"


def auth(token: str) -> dict[str, str]:
    """Build an Authorization header for the given bearer token."""
    return {"Authorization": f"Bearer {token}"}


@contextmanager
def capture_audit() -> Iterator[io.StringIO]:
    """Capture audit-logger output emitted while the block runs."""
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(JsonFormatter())
    audit = logging.getLogger(AUDIT_LOGGER_NAME)
    audit.addHandler(handler)
    try:
        yield buffer
    finally:
        audit.removeHandler(handler)


def audit_lines(buffer: io.StringIO) -> list[dict[str, str]]:
    """Parse captured audit output into a list of JSON event dicts."""
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A TestClient over a fresh secure app with its own seeded in-memory DB."""
    app = create_secure_app()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def vulnerable_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """A TestClient over the vulnerable app (acknowledged for the test process)."""
    monkeypatch.setenv("ALLOW_VULNERABLE_DEMO", "true")
    app = create_vulnerable_app()
    with TestClient(app) as test_client:
        yield test_client
