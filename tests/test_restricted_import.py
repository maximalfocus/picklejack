"""The defence-in-depth integrity-authenticated path: HMAC + restricted unpickle."""

from __future__ import annotations

import base64
import hashlib
import hmac
import pickle
from typing import Any

import httpx
from fastapi.testclient import TestClient

from picklejack.config import APP_CONFIG, DEMO_SENTINEL, FICTIONAL_INTEGRATION_SECRET
from tests.conftest import GLOBEX_TOKEN, audit_lines, auth, capture_audit

VERIFIED = "/workspace/import/verified"
GENERIC_DETAIL = "The snapshot could not be imported."

# A canary gadget: if the restricted unpickler ever resolved its global, the
# reduce would call ``_canary_touch``. It must be refused by find_class first.
_CANARY_TRIPPED = False


def _canary_touch() -> str:
    global _CANARY_TRIPPED
    _CANARY_TRIPPED = True
    return "tripped"


class _Gadget:
    def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
        return (_canary_touch, ())


def _signed(raw: bytes) -> dict[str, str]:
    signature = hmac.new(APP_CONFIG.signing_key, raw, hashlib.sha256).hexdigest()
    return {"data": base64.b64encode(raw).decode(), "signature": signature}


def _post_verified(client: TestClient, body: dict[str, str]) -> httpx.Response:
    response: httpx.Response = client.post(VERIFIED, headers=auth(GLOBEX_TOKEN), json=body)
    return response


def test_legitimate_signed_snapshot_is_accepted(client: TestClient) -> None:
    signed = client.get("/workspace/export/verified", headers=auth(GLOBEX_TOKEN)).json()
    response = _post_verified(client, {"data": signed["data"], "signature": signed["signature"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tenant"] == "globex"
    assert body["workspace"]["workspace_name"] == "Globex Ops Overview"
    assert body["import_mode"] == "integrity-authenticated"


def test_tampered_snapshot_is_rejected(client: TestClient) -> None:
    signed = client.get("/workspace/export/verified", headers=auth(GLOBEX_TOKEN)).json()
    raw = bytearray(base64.b64decode(signed["data"]))
    raw[-1] ^= 0x01  # flip a byte; the HMAC no longer matches
    tampered = {"data": base64.b64encode(bytes(raw)).decode(), "signature": signed["signature"]}
    with capture_audit() as buffer:
        response = _post_verified(client, tampered)
    assert response.status_code == 400
    assert response.json() == {"detail": GENERIC_DETAIL}
    assert len(audit_lines(buffer)) == 1


def test_unsigned_snapshot_is_rejected(client: TestClient) -> None:
    signed = client.get("/workspace/export/verified", headers=auth(GLOBEX_TOKEN)).json()
    response = _post_verified(client, {"data": signed["data"], "signature": "00" * 32})
    assert response.status_code == 400
    assert response.json() == {"detail": GENERIC_DETAIL}


def test_correctly_signed_gadget_never_executes(client: TestClient) -> None:
    """Even a correctly-signed __reduce__ gadget is refused before it can run."""
    global _CANARY_TRIPPED
    _CANARY_TRIPPED = False
    signed = _signed(pickle.dumps(_Gadget()))
    with capture_audit() as buffer:
        response = _post_verified(client, signed)
    assert response.status_code == 400
    assert response.json() == {"detail": GENERIC_DETAIL}
    assert _CANARY_TRIPPED is False  # the restricted unpickler refused the global
    assert len(audit_lines(buffer)) == 1


def test_correctly_signed_os_popen_gadget_is_blocked(client: TestClient) -> None:
    import os

    class _RCE:
        def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
            return (os.popen, ("id",))

    signed = _signed(pickle.dumps(_RCE()))
    response = _post_verified(client, signed)
    assert response.status_code == 400
    assert "uid=" not in response.text
    assert FICTIONAL_INTEGRATION_SECRET not in response.text
    assert DEMO_SENTINEL not in response.text


def test_rejection_emits_exactly_one_clean_audit_event(client: TestClient) -> None:
    with capture_audit() as buffer:
        response = _post_verified(client, {"data": "not-base64!!", "signature": "00"})
    assert response.status_code == 400
    events = audit_lines(buffer)
    assert len(events) == 1
    event = events[0]
    assert event["action"] == "workspace.import.verified"
    assert event["outcome"] == "rejected"
    assert event["actor"] == "mallory"
    assert event["tenant"] == "globex"
    assert event["correlation_id"] == response.headers["X-Correlation-ID"]

    raw = buffer.getvalue()
    assert GLOBEX_TOKEN not in raw
    assert "Bearer" not in raw
    assert FICTIONAL_INTEGRATION_SECRET not in raw


def test_successful_verified_import_emits_no_audit_event(client: TestClient) -> None:
    signed = client.get("/workspace/export/verified", headers=auth(GLOBEX_TOKEN)).json()
    with capture_audit() as buffer:
        response = _post_verified(
            client, {"data": signed["data"], "signature": signed["signature"]}
        )
    assert response.status_code == 200
    assert audit_lines(buffer) == []


def test_generic_rejection_reveals_no_allowlist_or_integrity_oracle(client: TestClient) -> None:
    signed = client.get("/workspace/export/verified", headers=auth(GLOBEX_TOKEN)).json()
    tampered = {"data": signed["data"], "signature": "00" * 32}
    gadget = _signed(pickle.dumps(_Gadget()))
    bodies = {
        _post_verified(client, tampered).text,
        _post_verified(client, gadget).text,
        _post_verified(client, {"data": "zzzz", "signature": "ff"}).text,
    }
    assert len(bodies) == 1
    only = bodies.pop().lower()
    for token in ("hmac", "signature", "allowlist", "builtins", "unpickl", "os.popen"):
        assert token not in only
