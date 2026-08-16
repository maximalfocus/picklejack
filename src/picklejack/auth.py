"""Demo authentication.

Static demo-only bearer tokens map to exactly one user and thereby one tenant.
Missing, malformed, and unknown credentials all receive the same generic
``401 Unauthorized`` with the standard bearer challenge, so no response
distinguishes them. Tokens and authorization headers are never logged.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from picklejack.db import get_session
from picklejack.domain.models import User

# auto_error=False lets us return one identical 401 for missing, malformed, and
# unknown credentials rather than leaking which case occurred.
_bearer = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "Bearer"},
    )


def authenticate(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    session: Annotated[Session, Depends(get_session)],
) -> User:
    """Resolve the authenticated user or raise a generic 401."""
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise _unauthorized()
    user = session.scalar(select(User).where(User.token == credentials.credentials))
    if user is None:
        raise _unauthorized()
    return user
