"""Database wiring: a single, freshly seeded in-memory SQLite database per app.

Each application instance owns its own in-memory database, seeded once at
startup. Request handlers only ever read; no code path mutates domain state, so
disposable fixture state is byte-for-byte identical before and after any run.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from picklejack.domain.fixtures import seed


def build_seeded_engine() -> Engine:
    """Create a new in-memory SQLite engine and seed the deterministic fixtures.

    ``StaticPool`` keeps a single shared connection so the in-memory database
    persists for the lifetime of the engine.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    with Session(engine) as session:
        seed(session)
    return engine


def get_session(request: Request) -> Iterator[Session]:
    """Yield a read-only session bound to the current app's seeded engine."""
    engine: Engine = request.app.state.engine
    with Session(engine) as session:
        yield session
