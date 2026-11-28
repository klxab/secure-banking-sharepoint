from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from src.api.schemas.rbac import (
    AvailableRoleResponse,
    RoleAssignmentRequest,
    UserPermissionsResponse,
    UserRolesResponse,
)
from src.database.session import get_database_session
from src.models.role import Role
from src.models.user import User
from src.models.user_role import UserRole
from src.security.audit import record_audit_event
from src.security.authorization import require_permission
from src.security.rbac import (
    assign_role,
    get_all_roles,
    get_user_permissions,
    get_user_roles,
    remove_role,
)

router = APIRouter(
    prefix="/rbac",
    tags=["Role-Based Access Control"],
)


@router.get(
    "/roles",
    response_model=list[AvailableRoleResponse],
)
def list_roles(
    current_user: User = Depends(require_permission("role:read")),
    db: Session = Depends(get_database_session),
):
    """List available system roles."""

    return get_all_roles(db)


@router.post(
    "/users/{user_id}/roles",
    response_model=UserRolesResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_user_role(
    user_id: UUID,
    request: RoleAssignmentRequest,
    http_request: Request,
    current_user: User = Depends(require_permission("role:assign")),
    db: Session = Depends(get_database_session),
):
    """Assign a role to a user and record the security event."""

    try:
        assign_role(
            db=db,
            user_id=user_id,
            role_name=request.role_name,
            assigned_by=current_user.id,
        )

        record_audit_event(
            db=db,
            action="rbac.role.assign",
            outcome="success",
            actor_user_id=current_user.id,
            target_type="user",
            target_id=str(user_id),
            ip_address=(
                http_request.client.host
                if http_request.client
                else None
            ),
            user_agent=http_request.headers.get("user-agent"),
            details={
                "role_name": request.role_name.lower(),
            },
        )

        # Role assignment and audit event are committed atomically.
        db.commit()

        return UserRolesResponse(
            user_id=user_id,
            roles=get_user_roles(db, user_id),
        )

    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The role assignment conflicts with an existing record.",
        ) from exc

    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Role assignment service temporarily unavailable.",
        ) from exc


@router.delete(
    "/users/{user_id}/roles/{role_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_user_role(
    user_id: UUID,
    role_name: str,
    http_request: Request,
    current_user: User = Depends(require_permission("role:assign")),
    db: Session = Depends(get_database_session),
):
    """Remove a role and record the security event."""

    try:
        # Lock the role row before checking administrator assignments.
        # assign_role() and remove_role() use the same locking strategy.
        role = db.scalar(
            select(Role)
            .where(Role.name == role_name.lower())
            .with_for_update()
        )

        if role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role does not exist.",
            )

        # Never allow removal of the final system administrator.
        if role.name == "system_admin":
            admin_count = db.scalar(
                select(func.count())
                .select_from(UserRole)
                .where(UserRole.role_id == role.id)
            )

            if admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cannot remove the last system administrator.",
                )

        removed = remove_role(
            db=db,
            user_id=user_id,
            role_name=role_name,
        )

        if not removed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User does not have this role.",
            )

        record_audit_event(
            db=db,
            action="rbac.role.remove",
            outcome="success",
            actor_user_id=current_user.id,
            target_type="user",
            target_id=str(user_id),
            ip_address=(
                http_request.client.host
                if http_request.client
                else None
            ),
            user_agent=http_request.headers.get("user-agent"),
            details={
                "role_name": role.name,
            },
        )

        # Role removal and audit event are committed atomically.
        db.commit()

        return None

    except HTTPException:
        db.rollback()
        raise

    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Role removal service temporarily unavailable.",
        ) from exc


@router.get(
    "/users/{user_id}/roles",
    response_model=UserRolesResponse,
)
def list_user_roles(
    user_id: UUID,
    current_user: User = Depends(require_permission("role:read")),
    db: Session = Depends(get_database_session),
):
    """List roles assigned to a user."""

    user = db.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not exist.",
        )

    return UserRolesResponse(
        user_id=user_id,
        roles=get_user_roles(db, user_id),
    )


@router.get(
    "/users/{user_id}/permissions",
    response_model=UserPermissionsResponse,
)
def list_user_permissions(
    user_id: UUID,
    current_user: User = Depends(require_permission("permission:read")),
    db: Session = Depends(get_database_session),
):
    """List effective permissions granted to a user."""

    user = db.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User does not exist.",
        )

    return UserPermissionsResponse(
        user_id=user_id,
        permissions=get_user_permissions(db, user_id),
    )
