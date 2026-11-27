
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database.connection import create_database_engine
from src.models.user import User
from src.models.user_session import UserSession
from src.security.authentication import (
    ACCOUNT_LOCKOUT_DURATION,
    MAX_FAILED_LOGIN_ATTEMPTS,
    authenticate_user,
    register_user,
)
from src.security.passwords import (
    MAX_PASSWORD_BYTES,
    verify_password,
)
from src.security.sessions import validate_session


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


def create_registered_user(db, username=None, email=None, password=None):
    return register_user(
        db,
        username=username or f"auth_{uuid.uuid4().hex[:12]}",
        email=email or f"{uuid.uuid4().hex}@example.com",
        password=password or "Strong-Test-Password-2026!",
    )


def test_registration_normalizes_username_and_email(db):
    user = register_user(
        db,
        username="  TestUser  ",
        email="  TEST@EXAMPLE.COM  ",
        password="Strong-Test-Password-2026!",
    )

    assert user.username == "testuser"
    assert user.email == "test@example.com"


def test_registration_stores_argon2id_hash_not_plaintext(db):
    password = "Strong-Test-Password-2026!"

    user = create_registered_user(db, password=password)

    assert user.password_hash != password
    assert user.password_hash.startswith("$argon2id$")
    assert verify_password(password, user.password_hash)


def test_registration_rejects_short_password(db):
    with pytest.raises(ValueError):
        create_registered_user(db, password="short")


def test_registration_rejects_invalid_username(db):
    with pytest.raises(ValueError):
        register_user(
            db,
            username="invalid username",
            email="valid@example.com",
            password="Strong-Test-Password-2026!",
        )


def test_registration_rejects_invalid_email(db):
    with pytest.raises(ValueError):
        register_user(
            db,
            username="validuser",
            email="invalid-email",
            password="Strong-Test-Password-2026!",
        )


def test_registration_rejects_malformed_email_addresses(db):
    malformed_emails = [
        "user@@example.com",
        "@example.com",
        "user@",
        "user@example",
        "user..name@example.com",
        "user@example..com",
        "user name@example.com",
    ]

    for email in malformed_emails:
        with pytest.raises(ValueError):
            register_user(
                db,
                username=f"user_{uuid.uuid4().hex[:12]}",
                email=email,
                password="Strong-Test-Password-2026!",
            )


def test_registration_rejects_password_over_utf8_byte_limit(db):
    oversized_password = (
        "A" * (MAX_PASSWORD_BYTES // 2)
        + "é" * (MAX_PASSWORD_BYTES // 2 + 1)
    )

    assert len(oversized_password.encode("utf-8")) > MAX_PASSWORD_BYTES

    with pytest.raises(ValueError):
        create_registered_user(db, password=oversized_password)


def test_login_with_username_creates_session(db):
    user = create_registered_user(db)

    result = authenticate_user(
        db,
        identifier=user.username,
        password="Strong-Test-Password-2026!",
    )

    assert result is not None

    authenticated_user, raw_token = result

    assert authenticated_user.id == user.id
    assert validate_session(db, raw_token) is not None


def test_login_with_email_creates_session(db):
    user = create_registered_user(db)

    result = authenticate_user(
        db,
        identifier=user.email,
        password="Strong-Test-Password-2026!",
    )

    assert result is not None
    assert result[0].id == user.id
    assert validate_session(db, result[1]) is not None


def test_incorrect_password_increments_failed_attempts(db):
    user = create_registered_user(db)

    result = authenticate_user(
        db,
        identifier=user.username,
        password="Wrong-Password-2026!",
    )

    assert result is None
    assert user.failed_login_attempts == 1
    assert user.locked_until is None


def test_oversized_login_password_increments_failed_attempts(db):
    user = create_registered_user(db)

    oversized_password = "A" * (MAX_PASSWORD_BYTES + 1)

    result = authenticate_user(
        db,
        identifier=user.username,
        password=oversized_password,
    )

    assert result is None
    assert user.failed_login_attempts == 1
    assert user.locked_until is None


def test_failed_login_does_not_create_session(db):
    user = create_registered_user(db)

    result = authenticate_user(
        db,
        identifier=user.username,
        password="Wrong-Password-2026!",
    )

    assert result is None

    sessions = db.scalars(
        select(UserSession).where(UserSession.user_id == user.id)
    ).all()

    assert sessions == []


def test_fifth_failed_attempt_locks_account(db):
    user = create_registered_user(db)

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        result = authenticate_user(
            db,
            identifier=user.username,
            password="Wrong-Password-2026!",
        )

        assert result is None

    assert user.failed_login_attempts == MAX_FAILED_LOGIN_ATTEMPTS
    assert user.locked_until is not None

    remaining = user.locked_until - datetime.now(timezone.utc)

    assert timedelta(0) < remaining <= ACCOUNT_LOCKOUT_DURATION


def test_locked_account_rejects_correct_password(db):
    user = create_registered_user(db)

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        authenticate_user(
            db,
            identifier=user.username,
            password="Wrong-Password-2026!",
        )

    result = authenticate_user(
        db,
        identifier=user.username,
        password="Strong-Test-Password-2026!",
    )

    assert result is None
    assert user.locked_until is not None
    assert user.failed_login_attempts == MAX_FAILED_LOGIN_ATTEMPTS


def test_expired_lockout_allows_successful_login(db):
    user = create_registered_user(db)

    user.failed_login_attempts = MAX_FAILED_LOGIN_ATTEMPTS
    user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.flush()

    result = authenticate_user(
        db,
        identifier=user.username,
        password="Strong-Test-Password-2026!",
    )

    assert result is not None
    assert user.failed_login_attempts == 0
    assert user.locked_until is None
    assert validate_session(db, result[1]) is not None


def test_successful_login_resets_previous_failed_attempts(db):
    user = create_registered_user(db)

    user.failed_login_attempts = 3
    db.flush()

    result = authenticate_user(
        db,
        identifier=user.username,
        password="Strong-Test-Password-2026!",
    )

    assert result is not None
    assert user.failed_login_attempts == 0
    assert user.locked_until is None


def test_inactive_account_cannot_authenticate(db):
    user = create_registered_user(db)
    user.is_active = False
    db.flush()

    result = authenticate_user(
        db,
        identifier=user.username,
        password="Strong-Test-Password-2026!",
    )

    assert result is None


def test_unknown_user_cannot_authenticate(db):
    result = authenticate_user(
        db,
        identifier="unknown_user",
        password="Strong-Test-Password-2026!",
    )

    assert result is None


def test_invalid_login_inputs_are_rejected(db):
    assert authenticate_user(db, "", "Some-Password-2026!") is None
    assert authenticate_user(db, "unknown_user", "") is None
    assert authenticate_user(db, None, "Some-Password-2026!") is None
    assert authenticate_user(db, "unknown_user", None) is None


def test_failed_login_attempt_persists_after_commit():
    engine = create_database_engine()
    username = f"persist_{uuid.uuid4().hex[:12]}"
    email = f"{uuid.uuid4().hex}@example.com"

    try:
        # Register and permanently commit the test user.
        with Session(engine) as db:
            user = register_user(
                db,
                username=username,
                email=email,
                password="Strong-Test-Password-2026!",
            )

            user_id = user.id
            db.commit()

        # Perform a failed login and commit the counter update.
        with Session(engine) as db:
            result = authenticate_user(
                db,
                identifier=username,
                password="Wrong-Password-2026!",
            )

            assert result is None
            db.commit()

        # Verify persistence using a completely new session.
        with Session(engine) as db:
            persisted_user = db.get(User, user_id)

            assert persisted_user is not None
            assert persisted_user.failed_login_attempts == 1
            assert persisted_user.locked_until is None

    finally:
        # Remove only this isolated test account.
        with Session(engine) as db:
            user = db.get(User, user_id)
            if user is not None:
                db.delete(user)
                db.commit()

        engine.dispose()
