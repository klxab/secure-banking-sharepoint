from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RoleAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_name: str = Field(
        min_length=1,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_-]+$",
    )


class UserRolesResponse(BaseModel):
    user_id: UUID
    roles: list[str]


class UserPermissionsResponse(BaseModel):
    user_id: UUID
    permissions: list[str]


class AvailableRoleResponse(BaseModel):
    name: str
    description: str | None
    is_system_role: bool