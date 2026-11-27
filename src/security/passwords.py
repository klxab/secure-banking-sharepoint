
from argon2 import PasswordHasher, Type
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

MAX_PASSWORD_BYTES = 1024

_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def _is_valid_password_input(password: str) -> bool:
    """Check password type and maximum UTF-8 byte length."""

    if not isinstance(password, str) or not password:
        return False

    try:
        return len(password.encode("utf-8")) <= MAX_PASSWORD_BYTES
    except UnicodeEncodeError:
        return False


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""

    if not _is_valid_password_input(password):
        raise ValueError(
            f"Password must be non-empty and no longer than "
            f"{MAX_PASSWORD_BYTES} UTF-8 bytes."
        )

    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its stored Argon2id hash."""

    if not _is_valid_password_input(password):
        return False

    if not isinstance(password_hash, str):
        return False

    try:
        return _password_hasher.verify(password_hash, password)

    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError,
    ):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    """Check whether a stored password hash needs updated parameters."""

    if not isinstance(password_hash, str):
        return True

    try:
        return _password_hasher.check_needs_rehash(password_hash)

    except (VerificationError, InvalidHashError):
        return True