"""Export issues a data-only snapshot of the caller's own workspace."""

from __future__ import annotations

import json

import yaml
from fastapi.testclient import TestClient

from tests.conftest import GLOBEX_TOKEN, INITECH_TOKEN, auth

_GLOBEX_VIEW = {
    "workspace_name": "Globex Ops Overview",
    "panels": [
        {"title": "Weekly Revenue", "kind": "line_chart", "position": 1},
        {"title": "Open Incidents", "kind": "counter", "position": 2},
        {"title": "Regional Breakdown", "kind": "bar_chart", "position": 3},
    ],
    "filters": [
        {"field": "region", "operator": "in", "value": "APAC,EMEA", "position": 1},
        {"field": "status", "operator": "eq", "value": "active", "position": 2},
    ],
}


def test_export_json_is_the_callers_own_workspace(client: TestClient) -> None:
    response = client.get("/workspace/export", headers=auth(GLOBEX_TOKEN))
    assert response.status_code == 200
    envelope = response.json()
    assert envelope["format"] == "json"
    assert json.loads(envelope["data"]) == _GLOBEX_VIEW


def test_export_yaml_is_the_callers_own_workspace(client: TestClient) -> None:
    response = client.get(
        "/workspace/export", params={"format": "yaml"}, headers=auth(GLOBEX_TOKEN)
    )
    assert response.status_code == 200
    envelope = response.json()
    assert envelope["format"] == "yaml"
    assert yaml.safe_load(envelope["data"]) == _GLOBEX_VIEW


def test_export_is_tenant_scoped(client: TestClient) -> None:
    globex = client.get("/workspace/export", headers=auth(GLOBEX_TOKEN)).json()
    initech = client.get("/workspace/export", headers=auth(INITECH_TOKEN)).json()
    assert json.loads(globex["data"])["workspace_name"] == "Globex Ops Overview"
    assert json.loads(initech["data"])["workspace_name"] == "Initech Field Metrics"


def test_export_is_deterministic(client: TestClient) -> None:
    first = client.get("/workspace/export", headers=auth(GLOBEX_TOKEN)).json()
    second = client.get("/workspace/export", headers=auth(GLOBEX_TOKEN)).json()
    assert first == second


def test_export_rejects_unknown_format_generically(client: TestClient) -> None:
    response = client.get(
        "/workspace/export", params={"format": "pickle"}, headers=auth(GLOBEX_TOKEN)
    )
    assert response.status_code == 400
    assert "pickle" not in response.text
    assert "json" not in response.text and "yaml" not in response.text
