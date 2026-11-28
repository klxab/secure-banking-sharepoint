from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from src.api.dependencies import get_current_user
from src.database.session import get_database_session
from src.models.permission import Permission
from src.models.role_permission import RolePermission
from src.models.user import User
from src.models.user_role import UserRole
from src.security.audit import record_audit_event


def user_has_permission(
    db: Session,
    user_id,
    permission_code: str,
) -> bool:
    """Check whether a user has a specific permission."""

    if not permission_code or not permission_code.strip():
        return False

    statement = (
        select(Permission.id)
        .join(
            RolePermission,
            RolePermission.permission_id == Permission.id,
        )
        .join(
            UserRole,
            UserRole.role_id == RolePermission.role_id,
        )
        .where(
            UserRole.user_id == user_id,
            Permission.code == permission_code,
        )
        .limit(1)
    )

    return db.scalar(statement) is not None


def require_permission(
    permission_code: str,
) -> Callable:
    """Create a FastAPI dependency requiring a specific permission."""

    if not permission_code or not permission_code.strip():
        raise ValueError("Permission code cannot be empty.")

    def permission_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ) -> User:
        allowed = user_has_permission(
            db=db,
            user_id=current_user.id,
            permission_code=permission_code,
        )

        if not allowed:
            try:
                record_audit_event(
                    db=db,
                    action="authorization.permission.denied",
                    outcome="denied",
                    actor_user_id=current_user.id,
                    target_type="permission",
                    target_id=permission_code,
                    ip_address=(
                        request.client.host
                        if request.client
                        else None
                    ),
                    user_agent=request.headers.get("user-agent"),
                    details={
                        "permission_code": permission_code,
                        "reason_code": "insufficient_permission",
                        "http_method": request.method,
                        "http_path": request.url.path,
                        "status_code": status.HTTP_403_FORBIDDEN,
                    },
                )

                # Commit the denial event independently of the
                # operation that was rejected.
                db.commit()

            except SQLAlchemyError as exc:
                db.rollback()

                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Security audit service temporarily unavailable.",
                ) from exc

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )

        return current_user

    return permission_checker
