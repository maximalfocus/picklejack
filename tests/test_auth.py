"""Authentication returns one generic 401 for missing, malformed, and unknown."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import GLOBEX_TOKEN, auth

_BODY = {"format": "json", "data": '{"workspace_name": "x", "panels": [], "filters": []}'}


def test_missing_credentials_are_generic_401(client: TestClient) -> None:
    response = client.post("/workspace/import", json=_BODY)
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_malformed_scheme_is_generic_401(client: TestClient) -> None:
    response = client.post(
        "/workspace/import",
        headers={"Authorization": "Basic Zm9vOmJhcg=="},
        json=_BODY,
    )
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_unknown_token_is_generic_401(client: TestClient) -> None:
    response = client.post("/workspace/import", headers=auth("nope-not-real"), json=_BODY)
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_all_rejections_are_indistinguishable(client: TestClient) -> None:
    missing = client.post("/workspace/import", json=_BODY)
    malformed = client.post(
        "/workspace/import",
        headers={"Authorization": "Basic Zm9vOmJhcg=="},
        json=_BODY,
    )
    unknown = client.post("/workspace/import", headers=auth("nope-not-real"), json=_BODY)
    bodies = {missing.text, malformed.text, unknown.text}
    statuses = {missing.status_code, malformed.status_code, unknown.status_code}
    assert statuses == {401}
    assert len(bodies) == 1


def test_valid_token_is_accepted(client: TestClient) -> None:
    response = client.post("/workspace/import", headers=auth(GLOBEX_TOKEN), json=_BODY)
    assert response.status_code == 200
