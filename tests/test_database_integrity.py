import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from src.database.connection import create_database_engine


@pytest.fixture
def connection():
    engine = create_database_engine()
    conn = engine.connect()
    transaction = conn.begin()

    yield conn

    transaction.rollback()
    conn.close()
    engine.dispose()


def create_test_user(connection, username, email):
    connection.execute(
        text("""
            INSERT INTO users (
                id,
                username,
                email,
                password_hash
            )
            VALUES (
                :id,
                :username,
                :email,
                :password_hash
            )
        """),
        {
            "id": str(uuid.uuid4()),
            "username": username,
            "email": email,
            "password_hash": "test_password_hash",
        },
    )


def test_duplicate_username_is_rejected(connection):
    create_test_user(
        connection,
        "testuser",
        "testuser1@example.com",
    )

    with pytest.raises(IntegrityError):
        with connection.begin_nested():
            create_test_user(
                connection,
                "TESTUSER",
                "testuser2@example.com",
            )


def test_duplicate_email_is_rejected(connection):
    create_test_user(
        connection,
        "testuser1",
        "test@example.com",
    )

    with pytest.raises(IntegrityError):
        with connection.begin_nested():
            create_test_user(
                connection,
                "testuser2",
                "TEST@EXAMPLE.COM",
            )

def test_negative_failed_login_attempts_are_rejected(connection):
    with pytest.raises(IntegrityError):
        with connection.begin_nested():
            connection.execute(
                text("""
                    INSERT INTO users (
                        id,
                        username,
                        email,
                        password_hash,
                        failed_login_attempts
                    )
                    VALUES (
                        :id,
                        :username,
                        :email,
                        :password_hash,
                        :failed_login_attempts
                    )
                """),
                {
                    "id": str(uuid.uuid4()),
                    "username": "negative_test",
                    "email": "negative@example.com",
                    "password_hash": "test_hash",
                    "failed_login_attempts": -1,
                },
            )


def test_user_role_invalid_foreign_key_is_rejected(connection):
    with pytest.raises(IntegrityError):
        with connection.begin_nested():
            connection.execute(
                text("""
                    INSERT INTO user_roles (
                        user_id,
                        role_id
                    )
                    VALUES (
                        :user_id,
                        :role_id
                    )
                """),
                {
                    "user_id": str(uuid.uuid4()),
                    "role_id": str(uuid.uuid4()),
                },
            )


def test_role_permission_invalid_foreign_key_is_rejected(connection):
    with pytest.raises(IntegrityError):
        with connection.begin_nested():
            connection.execute(
                text("""
                    INSERT INTO role_permissions (
                        role_id,
                        permission_id
                    )
                    VALUES (
                        :role_id,
                        :permission_id
                    )
                """),
                {
                    "role_id": str(uuid.uuid4()),
                    "permission_id": str(uuid.uuid4()),
                },
            )

def test_duplicate_user_role_assignment_is_rejected(connection):
    user_id = uuid.uuid4()
    role_id = uuid.uuid4()

    create_test_user(
        connection,
        "assignment_test_user",
        "assignment@example.com",
    )

    # Retrieve the user ID created by the helper.
    user_id = connection.execute(
        text("SELECT id FROM users WHERE username = :username"),
        {"username": "assignment_test_user"},
    ).scalar_one()

    connection.execute(
        text("""
            INSERT INTO roles (id, name)
            VALUES (:id, :name)
        """),
        {
            "id": str(role_id),
            "name": "assignment_test_role",
        },
    )

    connection.execute(
        text("""
            INSERT INTO user_roles (user_id, role_id)
            VALUES (:user_id, :role_id)
        """),
        {
            "user_id": str(user_id),
            "role_id": str(role_id),
        },
    )

    with pytest.raises(IntegrityError):
        with connection.begin_nested():
            connection.execute(
                text("""
                    INSERT INTO user_roles (user_id, role_id)
                    VALUES (:user_id, :role_id)
                """),
                {
                    "user_id": str(user_id),
                    "role_id": str(role_id),
                },
            )


def test_duplicate_role_permission_assignment_is_rejected(connection):
    role_id = uuid.uuid4()
    permission_id = uuid.uuid4()

    connection.execute(
        text("""
            INSERT INTO roles (id, name)
            VALUES (:id, :name)
        """),
        {
            "id": str(role_id),
            "name": "permission_test_role",
        },
    )

    connection.execute(
        text("""
            INSERT INTO permissions (id, code)
            VALUES (:id, :code)
        """),
        {
            "id": str(permission_id),
            "code": "test.permission",
        },
    )

    connection.execute(
        text("""
            INSERT INTO role_permissions (role_id, permission_id)
            VALUES (:role_id, :permission_id)
        """),
        {
            "role_id": str(role_id),
            "permission_id": str(permission_id),
        },
    )

    with pytest.raises(IntegrityError):
        with connection.begin_nested():
            connection.execute(
                text("""
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (:role_id, :permission_id)
                """),
                {
                    "role_id": str(role_id),
                    "permission_id": str(permission_id),
                },
            )