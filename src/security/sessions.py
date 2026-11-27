
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.models.user import User
from src.models.user_session import UserSession


DEFAULT_SESSION_LIFETIME = timedelta(hours=8)


def _hash_session_token(token: str) -> str:
    """Return the SHA-256 hexadecimal digest of a session token."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(
    db: Session,
    user_id: uuid.UUID,
    lifetime: timedelta = DEFAULT_SESSION_LIFETIME,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, UserSession]:
    """
    Create a session for an active user.

    Returns the raw token once and the corresponding database model.
    Only the SHA-256 token hash is stored in the database.
    The caller is responsible for committing the transaction.
    """

    if lifetime <= timedelta(0):
        raise ValueError("Session lifetime must be positive.")

    if ip_address is not None and len(ip_address) > 45:
        raise ValueError("IP address exceeds the maximum length.")

    if user_agent is not None and len(user_agent) > 512:
        raise ValueError("User agent exceeds the maximum length.")

    user = db.get(User, user_id)

    if user is None or not user.is_active:
        raise ValueError("Cannot create a session for this user.")

    now = datetime.now(timezone.utc)

    raw_token = secrets.token_urlsafe(32)

    session_record = UserSession(
        id=uuid.uuid4(),
        user_id=user_id,
        token_hash=_hash_session_token(raw_token),
        created_at=now,
        expires_at=now + lifetime,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.add(session_record)
    db.flush()

    return raw_token, session_record


def validate_session(
    db: Session,
    raw_token: str,
) -> UserSession | None:
    """
    Validate a session token.

    Returns the session record if it is valid.
    Returns None for invalid, expired, revoked or inactive-user sessions.

    The caller is responsible for committing the last-used timestamp.
    """

    if not isinstance(raw_token, str) or not raw_token:
        return None

    token_hash = _hash_session_token(raw_token)

    statement = select(UserSession).where(
        UserSession.token_hash == token_hash
    )

    session_record = db.scalar(statement)

    if session_record is None:
        return None

    now = datetime.now(timezone.utc)

    if session_record.revoked_at is not None:
        return None

    if session_record.expires_at <= now:
        return None

    user = db.get(User, session_record.user_id)

    if user is None or not user.is_active:
        return None

    session_record.last_used_at = now

    return session_record


def revoke_session(
    db: Session,
    raw_token: str,
) -> bool:
    """
    Revoke a session using its raw token.

    Returns True if a session was revoked.
    Returns False if the token is invalid or already revoked.

    The caller is responsible for committing the transaction.
    """

    if not isinstance(raw_token, str) or not raw_token:
        return False

    token_hash = _hash_session_token(raw_token)

    statement = select(UserSession).where(
        UserSession.token_hash == token_hash
    )

    session_record = db.scalar(statement)

    if session_record is None or session_record.revoked_at is not None:
        return False

    session_record.revoked_at = datetime.now(timezone.utc)

    return True


def revoke_all_user_sessions(
    db: Session,
    user_id: uuid.UUID,
) -> int:
    """
    Revoke all currently active sessions belonging to a user.

    Returns the number of sessions revoked.
    The caller is responsible for committing the transaction.
    """

    now = datetime.now(timezone.utc)

    statement = select(UserSession).where(
        UserSession.user_id == user_id,
        UserSession.revoked_at.is_(None),
        UserSession.expires_at > now,
    )

    active_sessions = db.scalars(statement).all()

    for session_record in active_sessions:
        session_record.revoked_at = now

    return len(active_sessions)
