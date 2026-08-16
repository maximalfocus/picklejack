"""The intentionally vulnerable snapshot boundary (LOCAL DEMO ONLY).

Reconstructs a submitted snapshot with an **unsafe deserializer on untrusted
bytes** — ``pickle.loads`` for the pickle format and ``yaml.load`` (the
object-constructing loader) for YAML — with **no integrity or authenticity check**.
This deliberately absent separation of *data* from *object reconstruction* is the
flaw. It exists only for local demonstration and must never be deployed.
"""

from __future__ import annotations

import base64
import json
import pickle  # unsafe on purpose: this module demonstrates the flaw
from typing import Any

import yaml

from picklejack.schemas import WorkspaceSnapshot
from picklejack.snapshots.common import FORMAT_JSON, FORMAT_YAML, SnapshotRejected

FORMAT_PICKLE = "pickle"


def load_vulnerable(fmt: str, data: str) -> tuple[str, Any]:
    """Reconstruct the snapshot with an unsafe deserializer; return (name, object).

    There is no integrity check: whatever bytes arrive are turned back into live
    objects, so a ``__reduce__`` or ``!!python/...`` payload runs during load.
    """
    if fmt == FORMAT_PICKLE:
        # UNSAFE: pickle.loads runs the object's __reduce__ on untrusted bytes.
        return "pickle.loads", pickle.loads(base64.b64decode(data))
    if fmt == FORMAT_YAML:
        # UNSAFE: the object-constructing loader executes !!python/... tags.
        return "yaml.load", yaml.load(data, Loader=yaml.UnsafeLoader)
    if fmt == FORMAT_JSON:
        # Benign baseline: json carries only primitive data, never objects.
        return "json.loads", json.loads(data)
    raise SnapshotRejected


def as_workspace(obj: Any) -> WorkspaceSnapshot | None:
    """Return the reconstructed object as a workspace view when it is a valid one."""
    if not isinstance(obj, dict):
        return None
    try:
        return WorkspaceSnapshot.model_validate(obj)
    except Exception:
        return None
