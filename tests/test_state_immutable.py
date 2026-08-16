"""No request path mutates domain state; fixtures are stable across a run."""

from __future__ import annotations

import base64
import pickle

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from picklejack.domain.models import Panel, SavedFilter, Workspace
from tests.conftest import GLOBEX_TOKEN, auth


def _state(client: TestClient) -> tuple[object, ...]:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as session:
        workspaces = [
            (w.id, w.tenant_id, w.name)
            for w in session.scalars(select(Workspace).order_by(Workspace.id)).all()
        ]
        panels = [
            (p.id, p.workspace_id, p.position, p.title, p.kind)
            for p in session.scalars(select(Panel).order_by(Panel.id)).all()
        ]
        filters = [
            (f.id, f.workspace_id, f.position, f.field, f.operator, f.value)
            for f in session.scalars(select(SavedFilter).order_by(SavedFilter.id)).all()
        ]
    return (tuple(workspaces), tuple(panels), tuple(filters))


def test_state_is_unchanged_after_many_operations(client: TestClient) -> None:
    before = _state(client)

    exported = client.get("/workspace/export", headers=auth(GLOBEX_TOKEN)).json()
    calls = [
        ("json", exported["data"]),
        ("json", '{"workspace_name": "x", "panels": [], "filters": [], "extra": 1}'),
        ("yaml", "!!python/object/apply:os.popen ['id']"),
        ("pickle", base64.b64encode(pickle.dumps({"a": 1})).decode()),
    ]
    for fmt, data in calls:
        client.post(
            "/workspace/import",
            headers=auth(GLOBEX_TOKEN),
            json={"format": fmt, "data": data},
        )

    assert _state(client) == before


def test_two_fresh_apps_seed_identically() -> None:
    from picklejack.apps.secure import create_secure_app

    first = create_secure_app()
    second = create_secure_app()
    with TestClient(first) as c1, TestClient(second) as c2:
        assert _state(c1) == _state(c2)
