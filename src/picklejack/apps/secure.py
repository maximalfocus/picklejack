"""The secure reporting-workspace application.

Exposes the same methods, paths, authentication contract, and success shape as the
(later) vulnerable app, but reconstructs a workspace only by **parsing a data-only
snapshot into an explicit schema**. It never reconstructs arbitrary objects from
untrusted input and contains no ``pickle`` path on any request-borne input, so a
forged snapshot, a pickle payload, and an unsafe-YAML payload are all rejected
generically without building anything.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from picklejack.auth import authenticate
from picklejack.db import build_seeded_engine, get_session
from picklejack.domain.models import User, Workspace
from picklejack.logging_setup import configure_logging
from picklejack.schemas import ImportResponse, SnapshotEnvelope
from picklejack.snapshots.common import FORMAT_JSON, FORMAT_YAML, SnapshotRejected
from picklejack.snapshots.secure import (
    decode_secure_snapshot,
    encode_snapshot,
    workspace_to_snapshot,
)

_SUPPORTED_EXPORT_FORMATS = (FORMAT_JSON, FORMAT_YAML)


def create_secure_app() -> FastAPI:
    """Build and return the secure FastAPI application."""
    configure_logging()

    app = FastAPI(
        title="picklejack (secure)",
        summary="Educational insecure-deserialization demo (secure app parses data into a schema).",
        version="0.1.0",
    )
    app.state.engine = build_seeded_engine()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    def _load_workspace(session: Session, user: User) -> Workspace:
        workspace = session.scalar(select(Workspace).where(Workspace.tenant_id == user.tenant_id))
        if workspace is None:  # pragma: no cover - every seeded tenant has a workspace
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workspace not found",
            )
        return workspace

    @app.get("/workspace/export", response_model=SnapshotEnvelope)
    def export_workspace(
        user: Annotated[User, Depends(authenticate)],
        session: Annotated[Session, Depends(get_session)],
        fmt: Annotated[str, Query(alias="format")] = FORMAT_JSON,
    ) -> SnapshotEnvelope:
        if fmt not in _SUPPORTED_EXPORT_FORMATS:
            # Generic: does not enumerate the accepted formats.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The workspace could not be exported.",
            )
        snapshot = workspace_to_snapshot(_load_workspace(session, user))
        return SnapshotEnvelope(format=fmt, data=encode_snapshot(snapshot, fmt))

    @app.post("/workspace/import", response_model=ImportResponse)
    def import_workspace(
        envelope: SnapshotEnvelope,
        user: Annotated[User, Depends(authenticate)],
    ) -> ImportResponse:
        try:
            snapshot = decode_secure_snapshot(envelope.format, envelope.data)
        except SnapshotRejected:
            # One generic response for every rejection cause: no object was
            # reconstructed, no secret is reachable, no command ran, and nothing
            # reveals which fields, types, or formats are accepted.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The snapshot could not be imported.",
            ) from None
        return ImportResponse(
            tenant=user.tenant.slug,
            workspace=snapshot,
            source_format=envelope.format,
            import_mode="data-into-schema",
        )

    return app
