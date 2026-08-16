"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from picklejack.apps.secure import create_secure_app

GLOBEX_TOKEN = "demo-token-globex-mallory"
INITECH_TOKEN = "demo-token-initech-peter"


def auth(token: str) -> dict[str, str]:
    """Build an Authorization header for the given bearer token."""
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client() -> Iterator[TestClient]:
    """A TestClient over a fresh secure app with its own seeded in-memory DB."""
    app = create_secure_app()
    with TestClient(app) as test_client:
        yield test_client
