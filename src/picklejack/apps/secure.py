"""The secure reporting-workspace application.

Exposes the same methods, paths, authentication contract, and success shape as the
(later) vulnerable app, but reconstructs a workspace only by **parsing a data-only
snapshot into an explicit schema**. It never reconstructs arbitrary objects from
untrusted input and contains no ``pickle`` path on any request-borne input, so a
forged snapshot, a pickle payload, and an unsafe-YAML payload are all rejected
generically without building anything.

It also offers a **secondary, defence-in-depth** integrity-authenticated import
path (HMAC + a restricted ``Unpickler`` with a type allowlist) for products that
cannot yet drop an opaque binary snapshot. Every snapshot rejection — on either
path — emits exactly one generic audit event and returns a correlation id.
"""

from __future__ import annotations

from typing import Annotated, NoReturn
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from picklejack.auth import authenticate
from picklejack.config import APP_CONFIG
from picklejack.db import build_seeded_engine, get_session
from picklejack.domain.models import User, Workspace
from picklejack.logging_setup import configure_logging, emit_audit_event
from picklejack.schemas import ImportResponse, SignedSnapshotEnvelope, SnapshotEnvelope
from picklejack.snapshots.common import FORMAT_JSON, FORMAT_YAML, SnapshotRejected
from picklejack.snapshots.restricted import sign_snapshot, verify_and_load_signed
from picklejack.snapshots.secure import (
    decode_secure_snapshot,
    encode_snapshot,
    workspace_to_snapshot,
)

_SUPPORTED_EXPORT_FORMATS = (FORMAT_JSON, FORMAT_YAML)
_GENERIC_IMPORT_DETAIL = "The snapshot could not be imported."


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

    def _reject(*, action: str, correlation_id: str, user: User) -> NoReturn:
        """Emit exactly one generic audit event and raise the generic 400.

        The response body is identical for every rejection cause (no field, type,
        format, allowlist, or integrity detail); only the audit event and the
        correlation id tie the rejection to server-side evidence.
        """
        emit_audit_event(
            action=action,
            outcome="rejected",
            correlation_id=correlation_id,
            actor=user.username,
            tenant=user.tenant.slug,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_GENERIC_IMPORT_DETAIL,
            headers={"X-Correlation-ID": correlation_id},
        )

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
        response: Response,
    ) -> ImportResponse:
        correlation_id = uuid4().hex
        response.headers["X-Correlation-ID"] = correlation_id
        try:
            snapshot = decode_secure_snapshot(envelope.format, envelope.data)
        except SnapshotRejected:
            # No object was reconstructed, no secret is reachable, no command ran,
            # and nothing reveals which fields, types, or formats are accepted.
            _reject(action="workspace.import", correlation_id=correlation_id, user=user)
        return ImportResponse(
            tenant=user.tenant.slug,
            workspace=snapshot,
            source_format=envelope.format,
            import_mode="data-into-schema",
        )

    @app.get("/workspace/export/verified", response_model=SignedSnapshotEnvelope)
    def export_workspace_verified(
        user: Annotated[User, Depends(authenticate)],
        session: Annotated[Session, Depends(get_session)],
    ) -> SignedSnapshotEnvelope:
        snapshot = workspace_to_snapshot(_load_workspace(session, user))
        data, signature = sign_snapshot(snapshot, APP_CONFIG.signing_key)
        return SignedSnapshotEnvelope(data=data, signature=signature)

    @app.post("/workspace/import/verified", response_model=ImportResponse)
    def import_workspace_verified(
        envelope: SignedSnapshotEnvelope,
        user: Annotated[User, Depends(authenticate)],
        response: Response,
    ) -> ImportResponse:
        correlation_id = uuid4().hex
        response.headers["X-Correlation-ID"] = correlation_id
        try:
            # Integrity is verified before deserialization; the restricted unpickler
            # then refuses any disallowed type before it can be constructed.
            snapshot = verify_and_load_signed(
                envelope.data, envelope.signature, APP_CONFIG.signing_key
            )
        except SnapshotRejected:
            _reject(action="workspace.import.verified", correlation_id=correlation_id, user=user)
        return ImportResponse(
            tenant=user.tenant.slug,
            workspace=snapshot,
            source_format="signed-pickle",
            import_mode="integrity-authenticated",
        )

    return app
