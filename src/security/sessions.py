
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import exists, select, update
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
    """Create a session for an active user."""

    if not isinstance(lifetime, timedelta) or lifetime <= timedelta(0):
        raise ValueError("Session lifetime must be positive.")

    if ip_address is not None and (
        not isinstance(ip_address, str) or len(ip_address) > 45
    ):
        raise ValueError("Invalid IP address metadata.")

    if user_agent is not None and (
        not isinstance(user_agent, str) or len(user_agent) > 512
    ):
        raise ValueError("Invalid user agent metadata.")

    user_statement = (
        select(User)
        .where(
            User.id == user_id,
            User.is_active.is_(True),
        )
        .with_for_update()
    )

    user = db.scalar(user_statement)

    if user is None:
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
    """Atomically validate and update a session's last-used timestamp."""

    if not isinstance(raw_token, str) or not raw_token:
        return None

    token_hash = _hash_session_token(raw_token)
    now = datetime.now(timezone.utc)

    active_user_exists = exists(
        select(User.id).where(
            User.id == UserSession.user_id,
            User.is_active.is_(True),
        )
    )

    statement = (
        update(UserSession)
        .where(
            UserSession.token_hash == token_hash,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
            active_user_exists,
        )
        .values(last_used_at=now)
        .returning(UserSession.id)
    )

    session_id = db.scalar(statement)

    if session_id is None:
        return None

    return db.get(UserSession, session_id, populate_existing=True)


def revoke_session(
    db: Session,
    raw_token: str,
) -> bool:
    """Atomically revoke a session using its raw token."""

    if not isinstance(raw_token, str) or not raw_token:
        return False

    token_hash = _hash_session_token(raw_token)
    now = datetime.now(timezone.utc)

    statement = (
        update(UserSession)
        .where(
            UserSession.token_hash == token_hash,
            UserSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
        .returning(UserSession.id)
    )

    session_id = db.scalar(statement)

    if session_id is None:
        return False

    db.expire_all()

    return True


def revoke_all_user_sessions(
    db: Session,
    user_id: uuid.UUID,
) -> int:
    """Atomically revoke all currently active sessions for a user."""

    now = datetime.now(timezone.utc)

    statement = (
        update(UserSession)
        .where(
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
        )
        .values(revoked_at=now)
        .returning(UserSession.id)
    )

    revoked_ids = db.scalars(statement).all()

    if revoked_ids:
        db.expire_all()

    return len(revoked_ids)
