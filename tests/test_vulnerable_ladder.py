"""The vulnerable app exhibits the full deserialization ladder (FR-004, FR-013).

Every payload executes only the single read-only command ``id`` and mutates no
domain state.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from picklejack.config import DEMO_SENTINEL, FICTIONAL_INTEGRATION_SECRET
from picklejack.domain.models import Panel, SavedFilter, Workspace
from picklejack.snapshots.attacker import (
    forged_pickle_snapshot,
    rce_pickle_snapshot,
    rce_yaml_snapshot,
    secret_pickle_snapshot,
    secret_yaml_snapshot,
)
from tests.conftest import GLOBEX_TOKEN, auth


def _import(vc: TestClient, fmt: str, data: str) -> dict[str, Any]:
    response = vc.post(
        "/workspace/import", headers=auth(GLOBEX_TOKEN), json={"format": fmt, "data": data}
    )
    assert response.status_code == 200, response.text
    result: dict[str, Any] = response.json()
    return result


def _state(vc: TestClient) -> tuple[Any, ...]:
    engine = vc.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as session:
        w = [(x.id, x.tenant_id, x.name) for x in session.scalars(select(Workspace)).all()]
        p = [(x.id, x.workspace_id, x.title, x.kind) for x in session.scalars(select(Panel)).all()]
        f = [
            (x.id, x.workspace_id, x.field, x.value)
            for x in session.scalars(select(SavedFilter)).all()
        ]
    return (tuple(w), tuple(p), tuple(f))


def test_forged_snapshot_is_accepted_without_integrity_check(vulnerable_client: TestClient) -> None:
    body = _import(vulnerable_client, "pickle", forged_pickle_snapshot())
    assert body["deserializer"] == "pickle.loads"
    assert body["reconstructed_from_untrusted_bytes"] is True
    # A snapshot the service never issued is trusted: attacker data is reconstructed.
    assert body["workspace"]["workspace_name"] == "Forged by attacker"


def test_pickle_object_injection_discloses_secret(vulnerable_client: TestClient) -> None:
    body = _import(vulnerable_client, "pickle", secret_pickle_snapshot())
    assert FICTIONAL_INTEGRATION_SECRET in body["reconstructed"]
    assert body["workspace"] is None  # not a workspace — an injected object


def test_yaml_object_injection_discloses_secret(vulnerable_client: TestClient) -> None:
    body = _import(vulnerable_client, "yaml", secret_yaml_snapshot())
    assert body["deserializer"] == "yaml.load"
    assert FICTIONAL_INTEGRATION_SECRET in body["reconstructed"]


def test_pickle_reduce_reaches_code_execution(vulnerable_client: TestClient) -> None:
    body = _import(vulnerable_client, "pickle", rce_pickle_snapshot())
    # A uid=…/gid=… line proves os.popen('id') executed inside the container.
    assert "uid=" in body["reconstructed"]
    assert "gid=" in body["reconstructed"]
    assert DEMO_SENTINEL in body["reconstructed"]  # in-container code reached app internals


def test_yaml_apply_reaches_code_execution(vulnerable_client: TestClient) -> None:
    body = _import(vulnerable_client, "yaml", rce_yaml_snapshot())
    assert "uid=" in body["reconstructed"]
    assert DEMO_SENTINEL in body["reconstructed"]


def test_only_the_id_command_produces_output(vulnerable_client: TestClient) -> None:
    # The reconstructed string is exactly `id` output followed by the sentinel, so no
    # command other than the read-only `id` produced output.
    body = _import(vulnerable_client, "pickle", rce_pickle_snapshot())
    assert body["reconstructed"].startswith("uid=")
    assert body["reconstructed"].endswith(DEMO_SENTINEL)


def test_ladder_leaves_domain_state_unchanged(vulnerable_client: TestClient) -> None:
    before = _state(vulnerable_client)
    ladder = [
        ("pickle", forged_pickle_snapshot()),
        ("pickle", secret_pickle_snapshot()),
        ("yaml", secret_yaml_snapshot()),
        ("pickle", rce_pickle_snapshot()),
        ("yaml", rce_yaml_snapshot()),
    ]
    for fmt, data in ladder:
        _import(vulnerable_client, fmt, data)
    assert _state(vulnerable_client) == before
