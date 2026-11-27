
import re
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from src.models.user import User
from src.security.passwords import (
    MAX_PASSWORD_BYTES,
    hash_password,
    password_needs_rehash,
    verify_password,
)
from src.security.sessions import (
    DEFAULT_SESSION_LIFETIME,
    create_session,
)


MAX_FAILED_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=15)
MIN_PASSWORD_LENGTH = 12

# Used to perform an Argon2id verification when the account
# cannot be authenticated. The supplied password is never used
# for this dummy verification.
_DUMMY_PASSWORD = "Dummy-Authentication-Password-Only"
_DUMMY_PASSWORD_HASH = hash_password(_DUMMY_PASSWORD)


def _dummy_password_verification() -> None:
    """Perform a fixed-cost password verification."""

    verify_password(_DUMMY_PASSWORD, _DUMMY_PASSWORD_HASH)


def _is_valid_email(email: str) -> bool:
    """
    Apply conservative email validation.

    This intentionally supports ordinary ASCII email addresses.
    Internationalized email addresses are not supported here.
    """

    if not isinstance(email, str) or len(email) > 255:
        return False

    if email.count("@") != 1:
        return False

    local_part, domain = email.rsplit("@", 1)

    if not local_part or not domain:
        return False

    if len(local_part) > 64:
        return False

    if local_part.startswith(".") or local_part.endswith("."):
        return False

    if ".." in local_part or ".." in domain:
        return False

    local_pattern = re.compile(
        r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$"
    )

    if not local_pattern.fullmatch(local_part):
        return False

    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
    )

    return bool(domain_pattern.fullmatch(domain))


def _record_failed_login(
    db: Session,
    user: User,
    now: datetime,
) -> None:
    """Record a failed login and apply account lockout when necessary."""

    user.failed_login_attempts += 1

    if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        user.locked_until = now + ACCOUNT_LOCKOUT_DURATION

    user.updated_at = now

    db.flush()


def register_user(
    db: Session,
    username: str,
    email: str,
    password: str,
) -> User:
    """
    Register a user with an Argon2id password hash.

    The caller is responsible for committing the transaction.

    Database uniqueness constraints remain authoritative.
    An IntegrityError caused by duplicate credentials must be
    handled by the caller with a transaction rollback.
    """

    if not isinstance(username, str):
        raise ValueError("Invalid username.")

    if not isinstance(email, str):
        raise ValueError("Invalid email address.")

    if not isinstance(password, str):
        raise ValueError("Invalid password.")

    username = username.strip().lower()
    email = email.strip().lower()

    if not 3 <= len(username) <= 50:
        raise ValueError("Username must contain 3 to 50 characters.")

    if (
        any(character.isspace() for character in username)
        or not all(
            character.isalnum() or character in "_.-"
            for character in username
        )
    ):
        raise ValueError("Username contains invalid characters.")

    if not _is_valid_email(email):
        raise ValueError("Invalid email address.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must contain at least "
            f"{MIN_PASSWORD_LENGTH} characters."
        )

    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError("Password exceeds the maximum allowed length.")

    user = User(
        id=uuid.uuid4(),
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_active=True,
        failed_login_attempts=0,
    )

    db.add(user)
    db.flush()

    return user


def authenticate_user(
    db: Session,
    identifier: str,
    password: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[User, str] | None:
    """
    Authenticate using a username or email address.

    Returns:
        (user, raw_session_token) on successful authentication.
        None on failed authentication.

    IMPORTANT TRANSACTION CONTRACT:

    The caller MUST commit the transaction after every returned
    result, including None, so failed-login counters and lockout
    changes are persisted.

    The caller must roll back the transaction if an exception occurs.

    PostgreSQL row locking serializes authentication attempts
    against the same user record.
    """

    if (
        not isinstance(identifier, str)
        or not identifier.strip()
        or len(identifier.strip()) > 255
    ):
        _dummy_password_verification()
        return None

    if not isinstance(password, str) or not password:
        _dummy_password_verification()
        return None

    normalized_identifier = identifier.strip().lower()

    statement = (
        select(User)
        .where(
            or_(
                func.lower(User.username) == normalized_identifier,
                func.lower(User.email) == normalized_identifier,
            )
        )
        .with_for_update()
    )

    user = db.scalar(statement)

    if user is None:
        _dummy_password_verification()
        return None

    if not user.is_active:
        _dummy_password_verification()
        return None

    now = datetime.now(timezone.utc)

    if user.locked_until is not None:
        if user.locked_until > now:
            _dummy_password_verification()
            return None

        # The previous lockout has expired.
        user.failed_login_attempts = 0
        user.locked_until = None

    # Oversized passwords are rejected without passing them
    # into the real password verification function.
    # Dummy verification keeps the expensive hash operation.
    password_bytes = password.encode("utf-8")

    if len(password_bytes) > MAX_PASSWORD_BYTES:
        _dummy_password_verification()
        _record_failed_login(db, user, now)
        return None

    if not verify_password(password, user.password_hash):
        _record_failed_login(db, user, now)
        return None

    # Successful authentication.
    user.failed_login_attempts = 0
    user.locked_until = None
    user.updated_at = now

    # Upgrade password hashing parameters if necessary.
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    raw_token, _ = create_session(
        db=db,
        user_id=user.id,
        lifetime=DEFAULT_SESSION_LIFETIME,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.flush()

    return user, raw_token
