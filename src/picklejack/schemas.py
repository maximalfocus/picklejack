"""Request and response contracts shared by the application(s).

``WorkspaceSnapshot`` is the **data-only** snapshot contract: an explicit,
allowlisted set of typed fields. The secure application only ever parses untrusted
input into this schema — it never reconstructs arbitrary objects — so a snapshot
that is not a valid data-only snapshot is rejected without constructing anything.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PanelData(BaseModel):
    """One dashboard panel — allowlisted, typed data fields only."""

    model_config = ConfigDict(extra="forbid")

    title: str
    kind: str
    position: int


class FilterData(BaseModel):
    """One saved filter — allowlisted, typed data fields only."""

    model_config = ConfigDict(extra="forbid")

    field: str
    operator: str
    value: str
    position: int


class WorkspaceSnapshot(BaseModel):
    """The data-only workspace snapshot: workspace name, panels, and filters.

    ``extra="forbid"`` means an attacker-authored field (for example one smuggling
    a secret) makes the whole snapshot invalid rather than being silently carried.
    """

    model_config = ConfigDict(extra="forbid")

    workspace_name: str
    panels: list[PanelData]
    filters: list[FilterData]


class SnapshotEnvelope(BaseModel):
    """Transport envelope: a declared serialization format and its encoded data.

    ``format`` is a free string (not an enumerated type) so a rejection never
    confirms which formats the service accepts.
    """

    format: str = Field(description="Serialization format of the snapshot data.")
    data: str = Field(description="The encoded snapshot payload.")


class ImportResponse(BaseModel):
    """The reconstructed workspace view and how it was produced."""

    tenant: str
    workspace: WorkspaceSnapshot
    source_format: str
    import_mode: str
