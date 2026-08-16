"""Unit proofs that the secure decoder parses data and never builds objects."""

from __future__ import annotations

import base64
import os
import pickle

import pytest

from picklejack.schemas import WorkspaceSnapshot
from picklejack.snapshots.common import SnapshotRejected
from picklejack.snapshots.secure import decode_secure_snapshot, encode_snapshot

_VALID = (
    '{"workspace_name": "W", "panels": [{"title": "P", "kind": "counter", "position": 1}],'
    ' "filters": []}'
)

# A canary object: if it were ever unpickled, ``_canary_touch`` would run and flip
# the module flag. The secure decoder must reject the pickle format first.
_CANARY_TRIPPED = False


def _canary_touch() -> str:
    global _CANARY_TRIPPED
    _CANARY_TRIPPED = True
    return "tripped"


class _Canary:
    def __reduce__(self) -> tuple[object, tuple[object, ...]]:
        return (_canary_touch, ())


def test_json_snapshot_parses_into_schema() -> None:
    snapshot = decode_secure_snapshot("json", _VALID)
    assert isinstance(snapshot, WorkspaceSnapshot)
    assert snapshot.workspace_name == "W"
    assert snapshot.panels[0].title == "P"


def test_yaml_snapshot_parses_into_schema() -> None:
    yaml_doc = "workspace_name: W\npanels: []\nfilters: []\n"
    snapshot = decode_secure_snapshot("yaml", yaml_doc)
    assert snapshot.workspace_name == "W"


def test_extra_field_is_rejected() -> None:
    with pytest.raises(SnapshotRejected):
        decode_secure_snapshot(
            "json", '{"workspace_name": "W", "panels": [], "filters": [], "x": 1}'
        )


def test_wrong_type_is_rejected() -> None:
    with pytest.raises(SnapshotRejected):
        decode_secure_snapshot("json", '{"workspace_name": 5, "panels": [], "filters": []}')


def test_unknown_format_is_rejected() -> None:
    with pytest.raises(SnapshotRejected):
        decode_secure_snapshot("pickle", "AAAA")


def test_pickle_snapshot_is_never_unpickled() -> None:
    global _CANARY_TRIPPED
    _CANARY_TRIPPED = False
    payload = base64.b64encode(pickle.dumps(_Canary())).decode()
    with pytest.raises(SnapshotRejected):
        decode_secure_snapshot("pickle", payload)
    assert _CANARY_TRIPPED is False


def test_unsafe_yaml_never_invokes_os_popen(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def _tripwire(cmd: str) -> object:  # pragma: no cover - must never run
        nonlocal called
        called = True
        raise AssertionError("os.popen must not be called by the secure path")

    monkeypatch.setattr(os, "popen", _tripwire)
    with pytest.raises(SnapshotRejected):
        decode_secure_snapshot("yaml", "!!python/object/apply:os.popen ['id']")
    assert called is False


def test_malformed_json_is_rejected() -> None:
    with pytest.raises(SnapshotRejected):
        decode_secure_snapshot("json", "{ not valid")


def test_encode_round_trips_through_json_and_yaml() -> None:
    snapshot = decode_secure_snapshot("json", _VALID)
    for fmt in ("json", "yaml"):
        again = decode_secure_snapshot(fmt, encode_snapshot(snapshot, fmt))
        assert again == snapshot
