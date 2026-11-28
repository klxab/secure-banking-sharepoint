import json
import re
import uuid
from typing import Any

from sqlalchemy.orm import Session

from src.models.audit_log import AuditLog


VALID_OUTCOMES = {"success", "failure", "denied"}

ALLOWED_DETAIL_KEYS = {
    "reason_code",
    "identifier_type",
    "session_id",
    "role_name",
    "permission_code",
    "http_method",
    "http_path",
    "status_code",
    "request_id",
}

MAX_DETAILS_BYTES = 2048
MAX_DETAIL_STRING_LENGTH = 512

ACTION_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,99}$")


def _validate_details(details: dict[str, Any]) -> dict[str, Any]:
    """Validate and serialize approved non-sensitive event metadata."""

    if not isinstance(details, dict):
        raise ValueError("Audit details must be a dictionary.")

    invalid_keys = set(details) - ALLOWED_DETAIL_KEYS

    if invalid_keys:
        raise ValueError(
            "Audit details contain unsupported metadata fields."
        )

    for key, value in details.items():
        if not isinstance(key, str):
            raise ValueError("Audit detail keys must be strings.")

        if value is not None and not isinstance(
            value,
            (str, int, float, bool),
        ):
            raise ValueError(
                f"Unsupported value type for audit detail: {key}."
            )

        if isinstance(value, str):
            if len(value) > MAX_DETAIL_STRING_LENGTH:
                raise ValueError(
                    f"Audit detail is too long: {key}."
                )

            if key in {"session_id", "request_id"} and value:
                try:
                    uuid.UUID(value)
                except ValueError as exc:
                    raise ValueError(
                        f"{key} must be a valid UUID."
                    ) from exc

    try:
        serialized = json.dumps(
            details,
            allow_nan=False,
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Audit details are not valid JSON."
        ) from exc

    if len(serialized.encode("utf-8")) > MAX_DETAILS_BYTES:
        raise ValueError(
            "Audit details exceed the maximum size."
        )

    return json.loads(serialized)


def record_audit_event(
    db: Session,
    action: str,
    outcome: str,
    actor_user_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """
    Add a security audit event to the current transaction.

    The caller is responsible for committing or rolling back.

    No password, password hash, session token, or arbitrary
    metadata is accepted by this service.
    """

    if not isinstance(action, str) or not ACTION_PATTERN.fullmatch(action):
        raise ValueError("Invalid audit action.")

    if not isinstance(outcome, str) or outcome not in VALID_OUTCOMES:
        raise ValueError("Invalid audit outcome.")

    if actor_user_id is not None and not isinstance(
        actor_user_id,
        uuid.UUID,
    ):
        raise ValueError("Invalid audit actor ID.")

    if target_type is not None:
        if not isinstance(target_type, str) or len(target_type) > 100:
            raise ValueError("Invalid audit target type.")

    if target_id is not None:
        if not isinstance(target_id, str) or len(target_id) > 128:
            raise ValueError("Invalid audit target ID.")

    if ip_address is not None:
        if not isinstance(ip_address, str) or len(ip_address) > 45:
            raise ValueError("Invalid audit IP address.")

    if user_agent is not None:
        if not isinstance(user_agent, str) or len(user_agent) > 512:
            raise ValueError("Invalid audit user agent.")

    safe_details = _validate_details(
        {} if details is None else details
    )

    event = AuditLog(
        actor_user_id=actor_user_id,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details=safe_details,
    )

    db.add(event)
    db.flush()

    return event
