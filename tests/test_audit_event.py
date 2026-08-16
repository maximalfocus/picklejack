"""Every secure-app snapshot rejection emits exactly one clean audit event.

Covers the primary ``POST /workspace/import`` path; the integrity-authenticated
path is covered in ``test_restricted_import``.
"""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from picklejack.config import FICTIONAL_INTEGRATION_SECRET
from tests.conftest import GLOBEX_TOKEN, audit_lines, auth, capture_audit

_FORGED = {
    "format": "json",
    "data": '{"workspace_name": "x", "panels": [], "filters": [], "extra": 1}',
}
_BENIGN = {"format": "json", "data": '{"workspace_name": "x", "panels": [], "filters": []}'}


def _import(client: TestClient, body: dict[str, str]) -> httpx.Response:
    response: httpx.Response = client.post(
        "/workspace/import", headers=auth(GLOBEX_TOKEN), json=body
    )
    return response


def test_primary_rejection_emits_exactly_one_clean_event(client: TestClient) -> None:
    with capture_audit() as buffer:
        response = _import(client, _FORGED)
    assert response.status_code == 400
    events = audit_lines(buffer)
    assert len(events) == 1
    event = events[0]
    assert event["action"] == "workspace.import"
    assert event["outcome"] == "rejected"
    assert event["actor"] == "mallory"
    assert event["tenant"] == "globex"
    assert event["correlation_id"] == response.headers["X-Correlation-ID"]


def test_primary_success_emits_no_event(client: TestClient) -> None:
    with capture_audit() as buffer:
        response = _import(client, _BENIGN)
    assert response.status_code == 200
    assert audit_lines(buffer) == []


def test_audit_event_leaks_no_token_snapshot_or_secret(client: TestClient) -> None:
    smuggle = {
        "format": "json",
        "data": '{"workspace_name": "x", "panels": [], "filters": [], "leak": "'
        + FICTIONAL_INTEGRATION_SECRET
        + '"}',
    }
    with capture_audit() as buffer:
        _import(client, smuggle)
    raw = buffer.getvalue()
    assert GLOBEX_TOKEN not in raw
    assert "Bearer" not in raw
    assert FICTIONAL_INTEGRATION_SECRET not in raw
    assert "workspace_name" not in raw  # the raw snapshot is not echoed


def test_unauthenticated_rejection_emits_no_event(client: TestClient) -> None:
    # A 401 is not a snapshot rejection: no actor/tenant is known, so no event.
    with capture_audit() as buffer:
        response = client.post(
            "/workspace/import", headers={"Authorization": "Bearer nope"}, json=_FORGED
        )
    assert response.status_code == 401
    assert audit_lines(buffer) == []
