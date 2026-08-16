"""Side-by-side contrast between the vulnerable and secure apps (FR-007, FR-013)."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from picklejack.config import DEMO_SENTINEL, FICTIONAL_INTEGRATION_SECRET
from picklejack.snapshots.attacker import (
    forged_pickle_snapshot,
    rce_pickle_snapshot,
    rce_yaml_snapshot,
    secret_pickle_snapshot,
    secret_yaml_snapshot,
)
from tests.conftest import GLOBEX_TOKEN, auth

# The identical snapshots the vulnerable app executes and the secure app must reject.
LADDER: list[tuple[str, str]] = [
    ("pickle", forged_pickle_snapshot()),
    ("pickle", secret_pickle_snapshot()),
    ("yaml", secret_yaml_snapshot()),
    ("pickle", rce_pickle_snapshot()),
    ("yaml", rce_yaml_snapshot()),
]


def _import(c: TestClient, fmt: str, data: str) -> Any:
    return c.post(
        "/workspace/import", headers=auth(GLOBEX_TOKEN), json={"format": fmt, "data": data}
    )


def test_benign_snapshot_is_identical_across_apps(
    client: TestClient, vulnerable_client: TestClient
) -> None:
    exported = client.get("/workspace/export", headers=auth(GLOBEX_TOKEN)).json()
    secure = _import(client, exported["format"], exported["data"]).json()
    vulnerable = _import(vulnerable_client, exported["format"], exported["data"]).json()
    assert secure["workspace"] == vulnerable["workspace"]
    assert secure["workspace"]["workspace_name"] == "Globex Ops Overview"


def test_secure_rejects_every_ladder_snapshot(client: TestClient) -> None:
    for fmt, data in LADDER:
        response = _import(client, fmt, data)
        assert response.status_code == 400, response.text
        assert response.json() == {"detail": "The snapshot could not be imported."}
        # No object reconstructed, no secret, no command output, no engine detail.
        assert FICTIONAL_INTEGRATION_SECRET not in response.text
        assert DEMO_SENTINEL not in response.text
        assert "uid=" not in response.text
        assert "Traceback" not in response.text


def test_vulnerable_executes_secret_and_rce(vulnerable_client: TestClient) -> None:
    secret = _import(vulnerable_client, "pickle", secret_pickle_snapshot()).json()["reconstructed"]
    assert FICTIONAL_INTEGRATION_SECRET in secret
    for fmt, data in (("pickle", rce_pickle_snapshot()), ("yaml", rce_yaml_snapshot())):
        reconstructed = _import(vulnerable_client, fmt, data).json()["reconstructed"]
        assert "uid=" in reconstructed


def test_both_apps_reject_unknown_auth_generically(
    client: TestClient, vulnerable_client: TestClient
) -> None:
    for c in (client, vulnerable_client):
        response = c.post(
            "/workspace/import",
            headers={"Authorization": "Bearer nope-not-real"},
            json={"format": "json", "data": "{}"},
        )
        assert response.status_code == 401
        assert response.headers.get("WWW-Authenticate") == "Bearer"
