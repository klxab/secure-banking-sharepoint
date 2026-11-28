from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.models.permission import Permission
from src.models.role import Role
from src.models.role_permission import RolePermission


ROLE_DEFINITIONS = {
    "system_admin": {
        "description": "Manages system configuration and identity administration.",
        "permissions": {
            "user:read",
            "user:create",
            "user:update",
            "role:read",
            "role:assign",
            "permission:read",
            "system:configure",
        },
    },
    "security_officer": {
        "description": "Reviews security events and manages security controls.",
        "permissions": {
            "security_event:read",
            "security_event:review",
            "security_event:manage",
            "audit_log:read",
        },
    },
    "bank_analyst": {
        "description": "Reads authorized banking accounts and transaction information.",
        "permissions": {
            "account:read",
            "transaction:read",
            "customer:read",
            "report:read",
        },
    },
    "customer_support": {
        "description": "Accesses limited customer support information.",
        "permissions": {
            "customer:read",
            "customer_support:read",
        },
    },
    "customer": {
        "description": "Accesses the customer's own banking information.",
        "permissions": {
            "account:read:self",
            "transaction:read:self",
            "profile:read:self",
            "profile:update:self",
        },
    },
    "auditor": {
        "description": "Reads authorized audit and security records.",
        "permissions": {
            "audit_log:read",
            "security_event:read",
            "report:read",
        },
    },
}


PERMISSION_DESCRIPTIONS = {
    "user:read": "Read user identity records.",
    "user:create": "Create user accounts.",
    "user:update": "Update user identity records.",
    "role:read": "Read role definitions and assignments.",
    "role:assign": "Assign roles to users.",
    "permission:read": "Read permission definitions.",
    "system:configure": "Manage approved system configuration.",
    "security_event:read": "Read security events.",
    "security_event:review": "Review and classify security events.",
    "security_event:manage": "Manage security event workflows.",
    "audit_log:read": "Read authorized audit records.",
    "account:read": "Read authorized banking account records.",
    "transaction:read": "Read authorized transaction records.",
    "customer:read": "Read authorized customer information.",
    "report:read": "Read authorized reports.",
    "customer_support:read": "Read limited customer support information.",
    "account:read:self": "Read only the authenticated customer's own accounts.",
    "transaction:read:self": "Read only the authenticated customer's own transactions.",
    "profile:read:self": "Read the authenticated customer's own profile.",
    "profile:update:self": "Update the authenticated customer's own profile.",
}


def seed_rbac(db: Session) -> dict[str, int]:
    """Create predefined RBAC roles, permissions, and assignments.

    The operation is idempotent. It does not assign roles to users
    or remove existing role-permission assignments.

    The caller is responsible for committing or rolling back.
    """

    permissions: dict[str, Permission] = {}
    roles: dict[str, Role] = {}

    created_permissions = 0
    created_roles = 0
    created_assignments = 0

    all_permission_codes = sorted(
        {
            permission_code
            for definition in ROLE_DEFINITIONS.values()
            for permission_code in definition["permissions"]
        }
    )

    for code in all_permission_codes:
        permission = db.scalar(
            select(Permission).where(
                func.lower(Permission.code) == code.lower()
            )
        )

        if permission is None:
            permission = Permission(
                code=code,
                description=PERMISSION_DESCRIPTIONS[code],
            )
            db.add(permission)
            db.flush()
            created_permissions += 1

        permissions[code] = permission

    for role_name, definition in ROLE_DEFINITIONS.items():
        role = db.scalar(
            select(Role).where(
                func.lower(Role.name) == role_name.lower()
            )
        )

        if role is None:
            role = Role(
                name=role_name,
                description=definition["description"],
                is_system_role=True,
            )
            db.add(role)
            db.flush()
            created_roles += 1

        roles[role_name] = role

        for permission_code in definition["permissions"]:
            permission = permissions[permission_code]

            assignment = db.get(
                RolePermission,
                (role.id, permission.id),
            )

            if assignment is None:
                db.add(
                    RolePermission(
                        role_id=role.id,
                        permission_id=permission.id,
                    )
                )
                created_assignments += 1

    db.flush()

    return {
        "roles_created": created_roles,
        "permissions_created": created_permissions,
        "assignments_created": created_assignments,
    }
