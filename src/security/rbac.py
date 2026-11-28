import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.models.permission import Permission
from src.models.role import Role
from src.models.role_permission import RolePermission
from src.models.user import User
from src.models.user_role import UserRole


def assign_role(
    db: Session,
    user_id: uuid.UUID,
    role_name: str,
    assigned_by: uuid.UUID,
) -> UserRole:
    """Assign an existing role to an active user."""

    user = db.get(User, user_id)

    if user is None or not user.is_active:
        raise ValueError("User does not exist or is inactive.")

    # Lock the role row to serialize concurrent role assignments
    # and removals involving the same role.
    role = db.scalar(
        select(Role)
        .where(Role.name == role_name.lower())
        .with_for_update()
    )

    if role is None:
        raise ValueError("Role does not exist.")

    if db.get(UserRole, (user_id, role.id)) is not None:
        raise ValueError("User already has this role.")

    assignment = UserRole(
        user_id=user_id,
        role_id=role.id,
        assigned_by=assigned_by,
    )

    db.add(assignment)
    db.flush()

    return assignment


def remove_role(
    db: Session,
    user_id: uuid.UUID,
    role_name: str,
) -> bool:
    """Remove a role assignment from a user."""

    # Use the same role-row locking strategy as assign_role().
    role = db.scalar(
        select(Role)
        .where(Role.name == role_name.lower())
        .with_for_update()
    )

    if role is None:
        raise ValueError("Role does not exist.")

    assignment = db.get(UserRole, (user_id, role.id))

    if assignment is None:
        return False

    db.delete(assignment)
    db.flush()

    return True


def get_user_roles(
    db: Session,
    user_id: uuid.UUID,
) -> list[str]:
    """Return all role names assigned to a user."""

    statement = (
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
        .order_by(Role.name)
    )

    return list(db.scalars(statement).all())


def get_user_permissions(
    db: Session,
    user_id: uuid.UUID,
) -> list[str]:
    """Return distinct permissions granted through assigned roles."""

    statement = (
        select(Permission.code)
        .join(
            RolePermission,
            RolePermission.permission_id == Permission.id,
        )
        .join(
            UserRole,
            UserRole.role_id == RolePermission.role_id,
        )
        .where(UserRole.user_id == user_id)
        .distinct()
        .order_by(Permission.code)
    )

    return list(db.scalars(statement).all())


def get_all_roles(db: Session) -> list[Role]:
    """Return all available roles."""

    statement = select(Role).order_by(Role.name)

    return list(db.scalars(statement).all())
