
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.models.user import User
from src.models.user_session import UserSession
from src.security.sessions import (
    create_session,
    revoke_all_user_sessions,
    revoke_session,
    validate_session,
)
from src.database.connection import create_database_engine


@pytest.fixture
def db():
    engine = create_database_engine()
    connection = engine.connect()
    transaction = connection.begin()

    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
    )

    yield session

    session.close()
    transaction.rollback()
    connection.close()
    engine.dispose()


@pytest.fixture
def test_user(db):
    user = User(
        username=f"session_test_{uuid.uuid4().hex[:12]}",
        email=f"{uuid.uuid4().hex}@example.com",
        password_hash="test-only-password-hash",
        is_active=True,
    )

    db.add(user)
    db.flush()

    return user


def test_session_creation_stores_only_token_hash(db, test_user):
    raw_token, session_record = create_session(db, test_user.id)

    expected_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    assert raw_token
    assert len(raw_token) > 0
    assert session_record.token_hash == expected_hash
    assert session_record.token_hash != raw_token
    assert len(session_record.token_hash) == 64
    assert session_record.user_id == test_user.id
    assert session_record.expires_at > session_record.created_at


def test_valid_session_is_accepted_and_last_used_updated(db, test_user):
    raw_token, session_record = create_session(db, test_user.id)

    assert session_record.last_used_at is None

    validated = validate_session(db, raw_token)

    assert validated is not None
    assert validated.id == session_record.id
    assert validated.last_used_at is not None


def test_invalid_token_is_rejected(db):
    assert validate_session(db, "invalid-session-token") is None


def test_expired_session_is_rejected(db, test_user):
    raw_token, session_record = create_session(db, test_user.id)

    now = datetime.now(timezone.utc)

    session_record.created_at = now - timedelta(hours=2)
    session_record.expires_at = now - timedelta(hours=1)
    db.flush()

    assert validate_session(db, raw_token) is None


def test_revoked_session_is_rejected(db, test_user):
    raw_token, session_record = create_session(db, test_user.id)

    assert revoke_session(db, raw_token) is True
    assert session_record.revoked_at is not None
    assert validate_session(db, raw_token) is None


def test_session_cannot_be_revoked_twice(db, test_user):
    raw_token, _ = create_session(db, test_user.id)

    assert revoke_session(db, raw_token) is True
    assert revoke_session(db, raw_token) is False


def test_all_active_user_sessions_can_be_revoked(db, test_user):
    token_one, session_one = create_session(db, test_user.id)
    token_two, session_two = create_session(db, test_user.id)

    revoked_count = revoke_all_user_sessions(db, test_user.id)

    assert revoked_count == 2
    assert session_one.revoked_at is not None
    assert session_two.revoked_at is not None
    assert validate_session(db, token_one) is None
    assert validate_session(db, token_two) is None


def test_inactive_user_session_is_rejected(db, test_user):
    raw_token, _ = create_session(db, test_user.id)

    test_user.is_active = False
    db.flush()

    assert validate_session(db, raw_token) is None


def test_session_cannot_be_created_for_inactive_user(db, test_user):
    test_user.is_active = False
    db.flush()

    with pytest.raises(ValueError):
        create_session(db, test_user.id)


def test_session_cannot_be_created_for_unknown_user(db):
    with pytest.raises(ValueError):
        create_session(db, uuid.uuid4())


def test_zero_or_negative_session_lifetime_is_rejected(db, test_user):
    with pytest.raises(ValueError):
        create_session(
            db,
            test_user.id,
            lifetime=timedelta(0),
        )

    with pytest.raises(ValueError):
        create_session(
            db,
            test_user.id,
            lifetime=timedelta(hours=-1),
        )


def test_invalid_or_empty_token_is_rejected(db):
    assert validate_session(db, "") is None
    assert validate_session(db, None) is None
    assert revoke_session(db, "") is False
    assert revoke_session(db, None) is False


def test_session_metadata_length_is_validated(db, test_user):
    with pytest.raises(ValueError):
        create_session(
            db,
            test_user.id,
            ip_address="1" * 46,
        )

    with pytest.raises(ValueError):
        create_session(
            db,
            test_user.id,
            user_agent="A" * 513,
        )


def test_unknown_token_cannot_be_revoked(db):
    assert revoke_session(db, "unknown-token") is False


def test_revoking_user_sessions_returns_zero_when_none_exist(db, test_user):
    assert revoke_all_user_sessions(db, test_user.id) == 0
