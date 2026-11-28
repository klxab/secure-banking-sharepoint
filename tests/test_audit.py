import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database.connection import create_database_engine
from src.models.audit_log import AuditLog
from src.security.audit import record_audit_event
from src.security.authentication import register_user


@pytest.fixture
def db():
    """Provide an isolated database transaction for each test."""

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


def create_test_user(db):
    """Create a test user inside the isolated transaction."""

    return register_user(
        db,
        username=f"audit_{uuid.uuid4().hex[:12]}",
        email=f"{uuid.uuid4().hex}@example.com",
        password="Strong-Test-Password-2026!",
    )


def test_successful_audit_event_is_created(db):
    user = create_test_user(db)

    event = record_audit_event(
        db=db,
        action="auth.login.success",
        outcome="success",
        actor_user_id=user.id,
        target_type="user",
        target_id=str(user.id),
        ip_address="127.0.0.1",
        user_agent="Audit-Test-Client",
        details={
            "identifier_type": "username",
        },
    )

    assert event.id is not None
    assert event.action == "auth.login.success"
    assert event.outcome == "success"
    assert event.actor_user_id == user.id
    assert event.target_type == "user"
    assert event.target_id == str(user.id)
    assert event.ip_address == "127.0.0.1"
    assert event.user_agent == "Audit-Test-Client"
    assert event.details == {
        "identifier_type": "username",
    }
    assert event.created_at is not None


def test_audit_event_is_retrievable_from_database(db):
    user = create_test_user(db)

    record_audit_event(
        db=db,
        action="rbac.role.assign",
        outcome="success",
        actor_user_id=user.id,
        target_type="user",
        target_id=str(user.id),
        details={
            "role_name": "customer",
        },
    )

    event = db.scalar(
        select(AuditLog).where(
            AuditLog.action == "rbac.role.assign",
            AuditLog.target_id == str(user.id),
        )
    )

    assert event is not None
    assert event.actor_user_id == user.id
    assert event.details["role_name"] == "customer"


def test_audit_event_can_be_rolled_back(db):
    event = record_audit_event(
        db=db,
        action="auth.login.success",
        outcome="success",
    )

    event_id = event.id

    db.rollback()

    persisted_event = db.get(AuditLog, event_id)

    assert persisted_event is None


def test_audit_event_rejects_invalid_action(db):
    invalid_actions = [
        "",
        "Invalid Action",
        "UPPERCASE",
        "invalid action",
        "a" * 101,
    ]

    for action in invalid_actions:
        with pytest.raises(ValueError):
            record_audit_event(
                db=db,
                action=action,
                outcome="success",
            )


def test_audit_event_rejects_invalid_outcome(db):
    invalid_outcomes = [
        "unknown",
        "SUCCESS",
        "",
        None,
        [],
    ]

    for outcome in invalid_outcomes:
        with pytest.raises(ValueError):
            record_audit_event(
                db=db,
                action="auth.login",
                outcome=outcome,
            )


def test_audit_event_rejects_unsupported_metadata(db):
    sensitive_fields = [
        {"password": "SecretPassword123!"},
        {"password_hash": "$argon2id$example"},
        {"session_token": "secret-session-token"},
        {"access_token": "secret-access-token"},
        {"secret": "private-value"},
    ]

    for details in sensitive_fields:
        with pytest.raises(ValueError):
            record_audit_event(
                db=db,
                action="auth.login.success",
                outcome="success",
                details=details,
            )


def test_audit_event_rejects_nested_metadata(db):
    invalid_details = {
        "role_name": {
            "nested": "value",
        }
    }

    with pytest.raises(ValueError):
        record_audit_event(
            db=db,
            action="rbac.role.assign",
            outcome="success",
            details=invalid_details,
        )


def test_audit_event_rejects_non_dictionary_details(db):
    invalid_details = [
        [],
        "invalid",
        123,
        False,
    ]

    for details in invalid_details:
        with pytest.raises(ValueError):
            record_audit_event(
                db=db,
                action="auth.login.success",
                outcome="success",
                details=details,
            )


def test_audit_event_rejects_oversized_metadata_values(db):
    with pytest.raises(ValueError):
        record_audit_event(
            db=db,
            action="rbac.role.assign",
            outcome="success",
            details={
                "role_name": "A" * 513,
            },
        )


def test_audit_event_rejects_oversized_user_agent(db):
    with pytest.raises(ValueError):
        record_audit_event(
            db=db,
            action="auth.login.success",
            outcome="success",
            user_agent="A" * 513,
        )


def test_audit_event_rejects_invalid_actor_id(db):
    with pytest.raises(ValueError):
        record_audit_event(
            db=db,
            action="auth.login.success",
            outcome="success",
            actor_user_id="not-a-uuid",
        )


def test_audit_event_rejects_invalid_session_uuid(db):
    with pytest.raises(ValueError):
        record_audit_event(
            db=db,
            action="auth.login.success",
            outcome="success",
            details={
                "session_id": "not-a-valid-uuid",
            },
        )


def test_audit_event_rejects_metadata_exceeding_size_limit(db):
    with pytest.raises(ValueError):
        record_audit_event(
            db=db,
            action="auth.login.success",
            outcome="success",
            details={
                "reason_code": "A" * 500,
                "identifier_type": "B" * 500,
                "role_name": "C" * 500,
                "permission_code": "D" * 500,
                "http_method": "E" * 500,
                "http_path": "F" * 500,
                "status_code": "G" * 500,
                "request_id": str(uuid.uuid4()),
                "session_id": str(uuid.uuid4()),
            },
        )
