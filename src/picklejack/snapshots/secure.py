"""The secure snapshot boundary: parse data into a schema, never build objects.

The secure application accepts only a **data-only** snapshot and validates it
against :class:`WorkspaceSnapshot`:

* ``json`` is parsed with :func:`json.loads` (primitive data only);
* ``yaml`` is read with :func:`yaml.safe_load`, which constructs only primitive
  data and **never** arbitrary Python objects — an object-constructing tag such as
  ``!!python/object/apply`` raises rather than executing.

There is **no ``pickle`` path** here and nothing is ever reconstructed as an
object. Any input that is not a valid data-only snapshot for the schema — a forged
snapshot, a pickle payload, an unsafe-YAML payload — raises
:class:`SnapshotRejected`, so the caller answers with one generic response.
"""

from __future__ import annotations

import json
from typing import Any

import yaml
from pydantic import ValidationError

from picklejack.domain.models import Workspace
from picklejack.schemas import FilterData, PanelData, WorkspaceSnapshot
from picklejack.snapshots.common import FORMAT_JSON, FORMAT_YAML, SnapshotRejected


def _parse_data_only(fmt: str, data: str) -> Any:
    """Parse the encoded snapshot into primitive data, or reject it.

    Neither branch can reconstruct an arbitrary Python object from the input.
    """
    if fmt == FORMAT_JSON:
        try:
            return json.loads(data)
        except (ValueError, TypeError) as exc:
            raise SnapshotRejected from exc
    if fmt == FORMAT_YAML:
        try:
            # safe_load constructs only primitive data; an object-constructing tag
            # (e.g. !!python/object/apply) raises here instead of executing.
            return yaml.safe_load(data)
        except yaml.YAMLError as exc:
            raise SnapshotRejected from exc
    # Any other declared format (including "pickle") has no secure path.
    raise SnapshotRejected


def decode_secure_snapshot(fmt: str, data: str) -> WorkspaceSnapshot:
    """Return the validated data-only snapshot, or raise :class:`SnapshotRejected`.

    The snapshot is reconstructed solely from allowlisted, typed data fields
    (workspace name, panels, filters); no attacker-authored object is built.
    """
    raw = _parse_data_only(fmt, data)
    try:
        return WorkspaceSnapshot.model_validate(raw)
    except ValidationError as exc:
        raise SnapshotRejected from exc


def workspace_to_snapshot(workspace: Workspace) -> WorkspaceSnapshot:
    """Build a data-only snapshot from a stored workspace (for export)."""
    return WorkspaceSnapshot(
        workspace_name=workspace.name,
        panels=[
            PanelData(title=p.title, kind=p.kind, position=p.position) for p in workspace.panels
        ],
        filters=[
            FilterData(field=f.field, operator=f.operator, value=f.value, position=f.position)
            for f in workspace.filters
        ],
    )


def encode_snapshot(snapshot: WorkspaceSnapshot, fmt: str) -> str:
    """Serialize a data-only snapshot for export in the requested format."""
    payload = snapshot.model_dump()
    if fmt == FORMAT_JSON:
        return json.dumps(payload, sort_keys=True)
    if fmt == FORMAT_YAML:
        return yaml.safe_dump(payload, sort_keys=True)
    raise SnapshotRejected
