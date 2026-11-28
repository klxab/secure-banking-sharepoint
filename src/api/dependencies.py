
from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database.session import get_database_session
from src.models.user import User
from src.security.sessions import validate_session


DatabaseSession = Annotated[
    Session,
    Depends(get_database_session),
]


def get_current_user(
    db: DatabaseSession,
    banking_session: Annotated[
        str | None,
        Cookie(alias="banking_session"),
    ] = None,
) -> User:
    """Resolve the authenticated user from the session cookie."""

    if not banking_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    session_record = validate_session(
        db=db,
        raw_token=banking_session,
    )

    if session_record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session.",
        )

    db.commit()

    user = db.get(User, session_record.user_id)

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive user session.",
        )

    return user
