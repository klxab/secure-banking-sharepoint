from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class UserRegistrationRequest(BaseModel):
    """Validated request data for user registration."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        min_length=3,
        max_length=50,
    )

    email: str = Field(
        min_length=3,
        max_length=255,
    )

    password: str = Field(
        min_length=12,
        max_length=1024,
    )


class UserResponse(BaseModel):
    """Safe public representation of a user."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    email: str
    is_active: bool
    created_at: datetime


class UserLoginRequest(BaseModel):
    """Validated request data for user login."""

    model_config = ConfigDict(extra="forbid")

    identifier: str = Field(
        min_length=1,
        max_length=255,
    )

    password: str = Field(
        min_length=1,
        max_length=1024,
    )
