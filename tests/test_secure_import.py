"""The secure import parses data into a schema and rejects everything else.

A benign server-issued snapshot round-trips to the caller's own workspace view; a
forged snapshot, a pickle payload, and an unsafe-YAML payload are each rejected
with one generic response that reconstructs no object, discloses no secret, and
reveals no field/type/format oracle.
"""

from __future__ import annotations

import base64
import json
import pickle

import httpx
from fastapi.testclient import TestClient

from picklejack.config import DEMO_SENTINEL, FICTIONAL_INTEGRATION_SECRET
from tests.conftest import GLOBEX_TOKEN, INITECH_TOKEN, auth

# A real pickle payload (benign dict bytes). The secure app has no pickle path, so
# it is refused by format without ever being unpickled.
PICKLE_SNAPSHOT = base64.b64encode(
    pickle.dumps({"workspace_name": "Forged", "panels": [], "filters": []})
).decode()

# An object-constructing YAML snapshot: yaml.safe_load refuses the tag.
UNSAFE_YAML = "!!python/object/apply:os.popen ['id']"

# A forged JSON snapshot the service never issued: smuggles an extra field.
FORGED_JSON = json.dumps(
    {"workspace_name": "Forged", "panels": [], "filters": [], "stolen_secret": "x"}
)


def _import(client: TestClient, token: str, fmt: str, data: str) -> httpx.Response:
    response: httpx.Response = client.post(
        "/workspace/import",
        headers=auth(token),
        json={"format": fmt, "data": data},
    )
    return response


def test_benign_json_round_trip_restores_own_workspace(client: TestClient) -> None:
    exported = client.get("/workspace/export", headers=auth(GLOBEX_TOKEN)).json()
    response = _import(client, GLOBEX_TOKEN, exported["format"], exported["data"])
    assert response.status_code == 200
    body = response.json()
    assert body["tenant"] == "globex"
    assert body["import_mode"] == "data-into-schema"
    assert body["source_format"] == "json"
    assert body["workspace"] == json.loads(exported["data"])


def test_benign_yaml_round_trip_restores_own_workspace(client: TestClient) -> None:
    exported = client.get(
        "/workspace/export", params={"format": "yaml"}, headers=auth(GLOBEX_TOKEN)
    ).json()
    response = _import(client, GLOBEX_TOKEN, exported["format"], exported["data"])
    assert response.status_code == 200
    body = response.json()
    assert body["tenant"] == "globex"
    assert body["workspace"]["workspace_name"] == "Globex Ops Overview"


def test_import_is_tenant_scoped(client: TestClient) -> None:
    exported = client.get("/workspace/export", headers=auth(GLOBEX_TOKEN)).json()
    # The same snapshot imported by another tenant is labelled with that caller's
    # tenant; it never returns another tenant's stored data.
    response = _import(client, INITECH_TOKEN, exported["format"], exported["data"])
    assert response.status_code == 200
    assert response.json()["tenant"] == "initech"


def test_forged_snapshot_is_rejected_generically(client: TestClient) -> None:
    response = _import(client, GLOBEX_TOKEN, "json", FORGED_JSON)
    assert response.status_code == 400
    assert response.json() == {"detail": "The snapshot could not be imported."}
    assert FICTIONAL_INTEGRATION_SECRET not in response.text


def test_pickle_snapshot_is_rejected_without_a_pickle_path(client: TestClient) -> None:
    response = _import(client, GLOBEX_TOKEN, "pickle", PICKLE_SNAPSHOT)
    assert response.status_code == 400
    assert response.json() == {"detail": "The snapshot could not be imported."}
    assert "uid=" not in response.text
    assert FICTIONAL_INTEGRATION_SECRET not in response.text


def test_unsafe_yaml_snapshot_does_not_execute(client: TestClient) -> None:
    response = _import(client, GLOBEX_TOKEN, "yaml", UNSAFE_YAML)
    assert response.status_code == 400
    assert response.json() == {"detail": "The snapshot could not be imported."}
    # yaml.safe_load never invoked os.popen('id'), so no id output crosses back.
    assert "uid=" not in response.text


def test_every_rejection_is_byte_identical_no_oracle(client: TestClient) -> None:
    responses = [
        _import(client, GLOBEX_TOKEN, "json", FORGED_JSON),
        _import(client, GLOBEX_TOKEN, "pickle", PICKLE_SNAPSHOT),
        _import(client, GLOBEX_TOKEN, "yaml", UNSAFE_YAML),
        _import(client, GLOBEX_TOKEN, "json", "not even json"),
        _import(client, GLOBEX_TOKEN, "yaml", "- 1\n- 2"),  # valid YAML, wrong shape
    ]
    bodies = {r.text for r in responses}
    assert {r.status_code for r in responses} == {400}
    assert len(bodies) == 1
    # The rejection reveals no accepted field, type, or format name.
    only = bodies.pop().lower()
    for token in (
        "workspace_name",
        "panels",
        "filters",
        "field required",
        "pickle",
        "yaml",
        "json",
    ):
        assert token not in only


def test_secret_never_appears_even_when_requested(client: TestClient) -> None:
    smuggle = json.dumps(
        {
            "workspace_name": "x",
            "panels": [],
            "filters": [],
            "integration_secret": FICTIONAL_INTEGRATION_SECRET,
            "demo_sentinel": DEMO_SENTINEL,
        }
    )
    response = _import(client, GLOBEX_TOKEN, "json", smuggle)
    # extra="forbid" rejects it; the echoed secret does not survive into output.
    assert response.status_code == 400
    assert FICTIONAL_INTEGRATION_SECRET not in response.text
    assert DEMO_SENTINEL not in response.text
