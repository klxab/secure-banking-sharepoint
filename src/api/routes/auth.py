import os
from typing import Annotated

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from src.api.dependencies import get_current_user
from src.api.schemas.auth import (
    UserLoginRequest,
    UserRegistrationRequest,
    UserResponse,
)
from src.database.session import get_database_session
from src.models.user import User
from src.security.audit import record_audit_event
from src.security.authentication import authenticate_user, register_user
from src.security.sessions import (
    DEFAULT_SESSION_LIFETIME,
    revoke_session,
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

COOKIE_SECURE = (
    os.getenv("COOKIE_SECURE", "false").strip().lower()
    in {"1", "true", "yes"}
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    request: UserRegistrationRequest,
    http_request: Request,
    db: Session = Depends(get_database_session),
) -> UserResponse:
    """Register a new user account and audit the operation."""

    try:
        user = register_user(
            db=db,
            username=request.username,
            email=request.email,
            password=request.password,
        )

        record_audit_event(
            db=db,
            action="auth.register.success",
            outcome="success",
            actor_user_id=user.id,
            target_type="user",
            target_id=str(user.id),
            ip_address=(
            http_request.client.host if http_request.client else None
            ),
            user_agent=http_request.headers.get("user-agent"),
        )

        db.commit()
        db.refresh(user)

        return user

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists.",
        )

    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registration service temporarily unavailable.",
        )

    except Exception:
        db.rollback()
        raise


@router.post("/login", response_model=UserResponse)
def login(
    request: Request,
    response: Response,
    credentials: UserLoginRequest,
    db: Session = Depends(get_database_session),
) -> UserResponse:
    """Authenticate a user and establish an audited session."""

    try:
        result = authenticate_user(
            db=db,
            identifier=credentials.identifier,
            password=credentials.password,
            ip_address=(
                request.client.host if request.client else None
            ),
            user_agent=request.headers.get("user-agent"),
        )

        if result is None:
            record_audit_event(
                db=db,
                action="auth.login.failure",
                outcome="failure",
                ip_address=(
                    request.client.host if request.client else None
                ),
                user_agent=request.headers.get("user-agent"),
                details={
                    "identifier_type": (
                        "email"
                        if "@" in credentials.identifier
                        else "username"
                    )
                },
            )

            db.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
            )

        user, raw_token = result

        record_audit_event(
            db=db,
            action="auth.login.success",
            outcome="success",
            actor_user_id=user.id,
            target_type="user",
            target_id=str(user.id),
            ip_address=(
                request.client.host if request.client else None
            ),
            user_agent=request.headers.get("user-agent"),
        )

        db.commit()
        db.refresh(user)

        response.set_cookie(
            key="banking_session",
            value=raw_token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="lax",
            max_age=int(DEFAULT_SESSION_LIFETIME.total_seconds()),
            path="/",
        )

        return user

    except HTTPException:
        raise

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service temporarily unavailable.",
        )

    except Exception:
        db.rollback()
        raise


@router.get("/me", response_model=UserResponse)
def get_authenticated_user(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return the currently authenticated user's profile."""

    return current_user


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_database_session),
    banking_session: Annotated[
        str | None,
        Cookie(alias="banking_session"),
    ] = None,
) -> Response:
    """Revoke the current session and audit the operation."""

    if not banking_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    try:
        revoked = revoke_session(
            db=db,
            raw_token=banking_session,
        )

        if not revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session.",
            )

        record_audit_event(
            db=db,
            action="auth.logout.success",
            outcome="success",
            actor_user_id=current_user.id,
            target_type="user",
            target_id=str(current_user.id),
            ip_address=(
                request.client.host if request.client else None
            ),
            user_agent=request.headers.get("user-agent"),
        )

        db.commit()

        response.delete_cookie(
            key="banking_session",
            path="/",
            secure=COOKIE_SECURE,
            httponly=True,
            samesite="lax",
        )

        return response

    except HTTPException:
        db.rollback()
        raise

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Session service temporarily unavailable.",
        )

    except Exception:
        db.rollback()
        raise
