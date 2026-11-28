
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from src.api.dependencies import get_current_user
from src.api.main import app
from src.database.connection import create_database_engine
from src.database.session import get_database_session
from src.models.audit_log import AuditLog
from src.models.permission import Permission
from src.models.role import Role
from src.models.role_permission import RolePermission
from src.models.user import User
from src.models.user_role import UserRole
from src.security.authentication import register_user


@pytest.fixture
def db():
    """Provide an isolated transaction against banking_test."""

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
    """Create a uniquely named test user."""

    return register_user(
        db,
        username=f"rbac_{uuid.uuid4().hex[:12]}",
        email=f"{uuid.uuid4().hex}@example.com",
        password="Strong-Test-Password-2026!",
    )


@pytest.fixture
def api_context(db):
    """
    Configure FastAPI with an isolated database connection
    and a test administrator.

    Authentication is overridden, but the actual RBAC
    authorization dependency remains active.
    """

    admin = create_test_user(db)

    system_admin_role = Role(
        name="system_admin",
        description="Test system administrator",
        is_system_role=True,
    )

    customer_role = Role(
        name="customer",
        description="Test customer role",
        is_system_role=True,
    )

    assign_permission = Permission(
        code="role:assign",
        description="Assign and remove user roles",
    )

    db.add_all([
        system_admin_role,
        customer_role,
        assign_permission,
    ])
    db.flush()

    db.add_all([
        RolePermission(
            role_id=system_admin_role.id,
            permission_id=assign_permission.id,
        ),
        UserRole(
            user_id=admin.id,
            role_id=system_admin_role.id,
            assigned_by=None,
        ),
    ])
    db.flush()

    def override_database_session():
        """
        Give each API request its own SQLAlchemy session.

        The session shares the outer test connection and uses
        a savepoint, so endpoint rollbacks do not remove
        the test fixture's previously created records.
        """

        request_db = Session(
            bind=db.get_bind(),
            join_transaction_mode="create_savepoint",
        )

        try:
            yield request_db
        finally:
            request_db.close()

    def override_authenticated_user():
        return admin

    app.dependency_overrides[get_database_session] = (
        override_database_session
    )

    app.dependency_overrides[get_current_user] = (
        override_authenticated_user
    )

    try:
        with TestClient(app) as client:
            yield {
                "client": client,
                "admin": admin,
                "system_admin_role": system_admin_role,
                "customer_role": customer_role,
                "db": db,
            }
    finally:
        app.dependency_overrides.clear()


def test_admin_can_assign_role_and_audit_event_is_created(
    api_context,
):
    client = api_context["client"]
    admin = api_context["admin"]
    customer_role = api_context["customer_role"]
    db = api_context["db"]

    target_user = create_test_user(db)

    response = client.post(
        f"/rbac/users/{target_user.id}/roles",
        json={"role_name": "customer"},
    )

    assert response.status_code == 201
    assert "customer" in response.json()["roles"]

    assignment = db.get(
        UserRole,
        (target_user.id, customer_role.id),
    )

    assert assignment is not None
    assert assignment.assigned_by == admin.id

    event = db.scalar(
        select(AuditLog).where(
            AuditLog.action == "rbac.role.assign",
            AuditLog.target_id == str(target_user.id),
        )
    )

    assert event is not None
    assert event.outcome == "success"
    assert event.actor_user_id == admin.id
    assert event.target_type == "user"
    assert event.details["role_name"] == "customer"


def test_admin_can_remove_role_and_audit_event_is_created(
    api_context,
):
    client = api_context["client"]
    admin = api_context["admin"]
    customer_role = api_context["customer_role"]
    db = api_context["db"]

    target_user = create_test_user(db)

    db.add(
        UserRole(
            user_id=target_user.id,
            role_id=customer_role.id,
            assigned_by=admin.id,
        )
    )
    db.flush()

    response = client.delete(
        f"/rbac/users/{target_user.id}/roles/customer"
    )

    assert response.status_code == 204

    assignment = db.get(
        UserRole,
        (target_user.id, customer_role.id),
    )

    assert assignment is None

    event = db.scalar(
        select(AuditLog).where(
            AuditLog.action == "rbac.role.remove",
            AuditLog.target_id == str(target_user.id),
        )
    )

    assert event is not None
    assert event.outcome == "success"
    assert event.actor_user_id == admin.id
    assert event.target_type == "user"
    assert event.details["role_name"] == "customer"


def test_duplicate_role_assignment_does_not_create_success_event(
    api_context,
):
    client = api_context["client"]
    admin = api_context["admin"]
    customer_role = api_context["customer_role"]
    db = api_context["db"]

    target_user = create_test_user(db)

    db.add(
        UserRole(
            user_id=target_user.id,
            role_id=customer_role.id,
            assigned_by=admin.id,
        )
    )
    db.flush()

    response = client.post(
        f"/rbac/users/{target_user.id}/roles",
        json={"role_name": "customer"},
    )

    assert response.status_code == 400

    events = db.scalars(
        select(AuditLog).where(
            AuditLog.action == "rbac.role.assign",
            AuditLog.target_id == str(target_user.id),
        )
    ).all()

    assert events == []


def test_last_system_administrator_cannot_be_removed(
    api_context,
):
    client = api_context["client"]
    admin = api_context["admin"]
    system_admin_role = api_context["system_admin_role"]
    db = api_context["db"]

    response = client.delete(
        f"/rbac/users/{admin.id}/roles/system_admin"
    )

    assert response.status_code == 409

    assert (
        response.json()["detail"]
        == "Cannot remove the last system administrator."
    )

    assignment = db.get(
        UserRole,
        (admin.id, system_admin_role.id),
    )

    assert assignment is not None

    events = db.scalars(
        select(AuditLog).where(
            AuditLog.action == "rbac.role.remove",
            AuditLog.target_id == str(admin.id),
        )
    ).all()

    assert events == []


def test_user_without_role_assign_permission_is_forbidden(
    api_context,
):
    client = api_context["client"]
    db = api_context["db"]

    unauthorized_user = create_test_user(db)
    target_user = create_test_user(db)

    def override_unauthorized_user():
        return unauthorized_user

    app.dependency_overrides[get_current_user] = (
        override_unauthorized_user
    )

    response = client.post(
        f"/rbac/users/{target_user.id}/roles",
        json={"role_name": "customer"},
    )

    assert response.status_code == 403

    assert (
        response.json()["detail"]
        == "You do not have permission to perform this action."
    )

    # Verify that the authorization denial was audited.
    event = db.scalar(
        select(AuditLog).where(
            AuditLog.action == "authorization.permission.denied",
            AuditLog.target_type == "permission",
            AuditLog.target_id == "role:assign",
            AuditLog.actor_user_id == unauthorized_user.id,
        )
    )

    assert event is not None
    assert event.outcome == "denied"
    assert event.actor_user_id == unauthorized_user.id
    assert event.details["permission_code"] == "role:assign"
    assert event.details["reason_code"] == "insufficient_permission"
    assert event.details["http_method"] == "POST"
    assert event.details["http_path"] == (
        f"/rbac/users/{target_user.id}/roles"
    )
    assert event.details["status_code"] == 403

    # Verify that the unauthorized operation did not assign a role.
    assignments = db.scalars(
        select(UserRole).where(
            UserRole.user_id == target_user.id,
        )
    ).all()

    assert assignments == []


def test_role_assignment_rolls_back_when_audit_insert_fails(
    api_context,
    monkeypatch,
):
    client = api_context["client"]
    customer_role = api_context["customer_role"]
    db = api_context["db"]

    target_user = create_test_user(db)

    def fail_audit_insert(*args, **kwargs):
        raise SQLAlchemyError(
            "Simulated audit database failure"
        )

    monkeypatch.setattr(
        "src.api.routes.rbac.record_audit_event",
        fail_audit_insert,
    )

    response = client.post(
        f"/rbac/users/{target_user.id}/roles",
        json={"role_name": "customer"},
    )

    assert response.status_code == 503

    assignment = db.get(
        UserRole,
        (target_user.id, customer_role.id),
    )

    assert assignment is None
