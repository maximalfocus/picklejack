"""The intentionally vulnerable reporting-workspace application (local demo only).

This app reconstructs the submitted snapshot with an **unsafe deserializer** and no
integrity check. It is dangerous by design and refuses to start unless the operator
explicitly acknowledges the risk with ``ALLOW_VULNERABLE_DEMO=true`` — the second of
two deliberate opt-in actions (the first being its opt-in Compose profile).

It exposes the same methods, paths, authentication contract, and successful response
shape as the secure app, so a benign snapshot yields an identical workspace view.
"""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from picklejack.auth import authenticate
from picklejack.db import build_seeded_engine, get_session
from picklejack.domain.models import User, Workspace
from picklejack.logging_setup import configure_logging
from picklejack.schemas import SnapshotEnvelope, VulnerableImportResponse
from picklejack.snapshots.common import FORMAT_JSON, SnapshotRejected
from picklejack.snapshots.secure import encode_snapshot, workspace_to_snapshot
from picklejack.snapshots.vulnerable import as_workspace, load_vulnerable

ALLOW_ENV = "ALLOW_VULNERABLE_DEMO"


class VulnerableDemoNotAllowed(RuntimeError):
    """Raised when the vulnerable app is started without explicit acknowledgement."""


def create_vulnerable_app() -> FastAPI:
    """Build the vulnerable app, or refuse without explicit acknowledgement."""
    if os.environ.get(ALLOW_ENV) != "true":
        raise VulnerableDemoNotAllowed(
            f"Refusing to start the vulnerable demo without {ALLOW_ENV}=true."
        )

    configure_logging()
    app = FastAPI(
        title="picklejack (VULNERABLE — local educational demo only)",
        summary="Intentionally vulnerable: rebuilds objects from untrusted bytes. Never deploy.",
        version="0.1.0",
    )
    app.state.engine = build_seeded_engine()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    def _load_workspace(session: Session, user: User) -> Workspace:
        workspace = session.scalar(select(Workspace).where(Workspace.tenant_id == user.tenant_id))
        if workspace is None:  # pragma: no cover - every seeded tenant has a workspace
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
        return workspace

    @app.get("/workspace/export", response_model=SnapshotEnvelope)
    def export_workspace(
        user: Annotated[User, Depends(authenticate)],
        session: Annotated[Session, Depends(get_session)],
        fmt: Annotated[str, Query(alias="format")] = FORMAT_JSON,
    ) -> SnapshotEnvelope:
        snapshot = workspace_to_snapshot(_load_workspace(session, user))
        return SnapshotEnvelope(format=fmt, data=encode_snapshot(snapshot, FORMAT_JSON))

    @app.post("/workspace/import", response_model=VulnerableImportResponse)
    def import_workspace(
        envelope: SnapshotEnvelope,
        user: Annotated[User, Depends(authenticate)],
    ) -> VulnerableImportResponse:
        # The flaw: reconstruct arbitrary objects from untrusted bytes, no integrity
        # check. Any __reduce__ / !!python/... payload runs here, during load.
        try:
            deserializer, obj = load_vulnerable(envelope.format, envelope.data)
        except SnapshotRejected:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported snapshot format.",
            ) from None
        return VulnerableImportResponse(
            tenant=user.tenant.slug,
            deserializer=deserializer,
            reconstructed_from_untrusted_bytes=envelope.format != FORMAT_JSON,
            reconstructed=str(obj),
            workspace=as_workspace(obj),
            import_mode="reconstructed-object",
        )

    return app
