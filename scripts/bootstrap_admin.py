import getpass
import sys

from sqlalchemy import func, select

from src.database.session import SessionLocal
from src.models.role import Role
from src.models.user import User
from src.models.user_role import UserRole
from src.security.passwords import hash_password, verify_password


ADMIN_USERNAME = "platform.admin"
ADMIN_EMAIL = "platform.admin@securebank.test"


def main() -> None:
    db = SessionLocal()

    try:
        # Lock the system_admin role to serialize bootstrap attempts.
        admin_role = db.scalar(
            select(Role)
            .where(Role.name == "system_admin")
            .with_for_update()
        )

        if admin_role is None or not admin_role.is_system_role:
            raise RuntimeError(
                "The expected system_admin system role was not found."
            )

        # Refuse to bootstrap if an administrator already exists.
        existing_admin_count = db.scalar(
            select(func.count())
            .select_from(UserRole)
            .where(UserRole.role_id == admin_role.id)
        )

        if existing_admin_count:
            raise RuntimeError(
                "An administrator already exists. Bootstrap refused."
            )

        # Lock and locate the specifically designated account.
        user = db.scalar(
            select(User)
            .where(
                func.lower(User.username) == ADMIN_USERNAME,
                func.lower(User.email) == ADMIN_EMAIL,
            )
            .with_for_update()
        )

        if user is None:
            raise RuntimeError(
                "The designated administrator account was not found."
            )

        if not user.is_active:
            raise RuntimeError(
                "The designated administrator account is inactive."
            )

        if db.get(UserRole, (user.id, admin_role.id)) is not None:
            raise RuntimeError(
                "The account already has the system_admin role."
            )

        print("Initial administrator password setup")
        print("Enter a NEW unique password. Do not reuse the exposed one.")

        password = getpass.getpass("New password: ")
        confirmation = getpass.getpass("Confirm new password: ")

        if password != confirmation:
            raise ValueError("The passwords do not match.")

        if len(password) < 12:
            raise ValueError(
                "The password must contain at least 12 characters."
            )

        if len(password.encode("utf-8")) > 1024:
            raise ValueError(
                "The password exceeds the maximum allowed length."
            )

        if verify_password(password, user.password_hash):
            raise ValueError(
                "Choose a new password, not the previously exposed password."
            )

        # Replace the exposed password using the existing Argon2id hasher.
        user.password_hash = hash_password(password)
        user.failed_login_attempts = 0
        user.locked_until = None

        # The first administrator has no existing administrator to authorize
        # this initial assignment, so assigned_by is intentionally NULL.
        db.add(
            UserRole(
                user_id=user.id,
                role_id=admin_role.id,
                assigned_by=None,
            )
        )

        # Password replacement and role assignment are atomic.
        db.commit()

        print("\nInitial administrator bootstrapped successfully.")
        print(f"Username: {user.username}")
        print(f"User ID: {user.id}")
        print("Role: system_admin")
        print("Password: updated and stored as an Argon2id hash.")

    except Exception as exc:
        db.rollback()
        print(f"\nBootstrap failed: {exc}")
        sys.exit(1)

    finally:
        db.close()


if __name__ == "__main__":
    main()