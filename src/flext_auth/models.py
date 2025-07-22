"""Authentication models with Python 3.13 advanced patterns and Pydantic standardization."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from flext_core import DomainEntity, DomainValueObject, Field

# Import types needed for Pydantic model_rebuild at runtime

if TYPE_CHECKING:
    from flext_core.domain.shared_types import EntityId, UserId

    from flext_auth.types import PermissionScope

# Python 3.13 type aliases for zero boilerplate
PermissionSet = frozenset[str]
RoleSet = frozenset[str]
Claims = dict[str, Any]


class AuthStatus(StrEnum):
    """Authentication status enum using flext-core patterns.

    This enumeration defines the possible authentication states for a user
    account, including active, inactive, locked, suspended, and expired
    statuses for comprehensive access control.

    Note:
    ----
        Implements enterprise authentication state management patterns.

    """

    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    SUSPENDED = "suspended"
    EXPIRED = "expired"


class UserRoleEnum(StrEnum):
    """User role enum for access control using flext-core patterns."""

    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    USER = "user"
    SERVICE = "service"
    READONLY = "readonly"
    DEVELOPER = "developer"
    AUDITOR = "auditor"

    @classmethod
    def create(
        cls,
        name: str,
        permissions: list[Permission],
        description: str = "",
    ) -> Role:
        """Create a new role with the given permissions.

        Args:
            name: The name of the role.
            permissions: List of Permission objects to assign to this role.
            description: Optional description of the role.

        Returns:
            A new Role instance with the specified permissions.

        """
        permission_names = {perm.name for perm in permissions}
        return Role(
            name=name,
            permissions=frozenset(permission_names),
            description=description,
        )


class Permission(DomainValueObject):
    """Permission value object with Pydantic validation and Python 3.13 features."""

    id: str | None = None
    resource: str
    action: str = ""
    scope: str = ""
    description: str = ""

    @property
    def name(self) -> str:
        """Get the permission name in resource:action format.

        Returns:
            Permission name formatted as "resource:action".

        """
        return f"{self.resource}:{self.action}"

    @classmethod
    def create(
        cls,
        name: str,
        scope: PermissionScope,
        resource: str,
        description: str = "",
    ) -> Permission:
        """Create a new permission with the given parameters.

        Args:
            name: The permission name (may be in action_resource format).
            scope: The scope of the permission.
            resource: The resource this permission applies to.
            description: Optional description of the permission.

        Returns:
            A new Permission instance.

        """
        # Extract action from name if it follows pattern "action_resource":
        if "_" in name:
            action, _resource_part = name.split("_", 1)
        else:
            action = name

        return cls(
            id=name,
            resource=resource,
            action=action,
            scope=scope,
            description=description,
        )


class Role(DomainValueObject):
    """Role value object with automatic permission aggregation and Pydantic validation."""

    name: str = Field(min_length=1)
    permissions: PermissionSet = Field(default_factory=frozenset)
    description: str = ""

    @property
    def id(self) -> str:
        """Get the role identifier, which is the role name.

        Returns:
            The role name as identifier.

        """
        return self.name

    def has_permission(self, permission: Permission) -> bool:
        """Check if this role has a specific permission.

        Args:
            permission: The Permission to check for.

        Returns:
            True if the role has the permission, False otherwise.

        """
        return permission.name in self.permissions


class User(DomainEntity):
    """User entity with Pydantic validation and domain entity patterns."""

    user_id: UserId = Field(default_factory=uuid4)
    username: str = ""
    email: str = ""
    password_hash: str = ""
    roles: frozenset[str] = Field(default_factory=frozenset)
    status: AuthStatus = AuthStatus.ACTIVE
    last_login: datetime | None = None
    failed_attempts: int = 0
    locked_until: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        """Check if the user account is active and not locked.

        Returns:
            True if the user is active and not locked, False otherwise.

        """
        # Handle both enum and enum value due to Pydantic use_enum_values=True
        status_active = self.status in {AuthStatus.ACTIVE, AuthStatus.ACTIVE.value}
        return status_active and not self.is_locked

    @property
    def is_locked(self) -> bool:
        """Check if the user account is currently locked.

        Returns:
            True if the account is locked (either temporarily or by status), False otherwise.

        """
        if self.locked_until:
            return datetime.now(UTC) < self.locked_until
        # Handle both enum and enum value due to Pydantic use_enum_values=True
        return self.status in {AuthStatus.LOCKED, AuthStatus.LOCKED.value}

    def has_role(self, role_name: str) -> bool:
        """Check if the user has a specific role.

        Args:
            role_name: The name of the role to check for.

        Returns:
            True if the user has the role, False otherwise.

        """
        return role_name in self.roles

    def add_role(self, role: Role) -> None:
        """Add a role to the user and update the timestamp.

        Args:
            role: The Role to add to this user.

        """
        self.roles |= {role.name}
        self.updated_at = datetime.now(UTC)

    def get_active_roles(self) -> list[Role]:
        """Get all active roles for this user.

        Returns:
            List of Role objects that are currently active for this user.

        """
        # Import here to avoid circular imports
        active_roles = []
        for role_name in self.roles:
            if role_name == "REDACTED_LDAP_BIND_PASSWORD":
                active_roles.append(ADMIN_ROLE)
            elif role_name == "operator":
                active_roles.append(OPERATOR_ROLE)
            elif role_name == "viewer":
                active_roles.append(VIEWER_ROLE)
        return active_roles

    def record_login(self) -> None:
        """Record a successful login, clearing failed attempts and locks."""
        self.last_login = datetime.now(UTC)
        self.failed_attempts = 0
        self.locked_until = None

    def record_failed_attempt(
        self,
        lock_after: int = 5,
        lock_duration_minutes: int = 30,
    ) -> None:
        """Record a failed login attempt and lock the account if threshold is reached.

        Args:
            lock_after: Number of failed attempts before locking (default: 5).
            lock_duration_minutes: Duration to lock the account in minutes (default: 30).

        """
        self.failed_attempts += 1
        if self.failed_attempts >= lock_after:
            self.locked_until = datetime.now(UTC).replace(
                minute=datetime.now(UTC).minute + lock_duration_minutes,
            )

    def to_claims(self) -> Claims:
        """Convert user data to JWT claims dictionary.

        Returns:
            Dictionary containing user claims suitable for JWT tokens.

        """
        try:
            status_name = self.status.name
        except AttributeError:
            # status is likely a string value, convert back to enum
            status_name = AuthStatus(self.status).name

        return {
            "sub": str(self.user_id),
            "username": self.username,
            "email": self.email,
            "roles": list(self.roles),
            "status": status_name,
            "metadata": self.metadata,
        }


class TokenInfo(DomainValueObject):
    """Token information with Pydantic validation and automatic validation."""

    token_id: EntityId = Field(default_factory=uuid4)
    user_id: UserId = Field(default_factory=uuid4)
    token_type: str = Field(default="access", description="Token type identifier")
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    revoked_at: datetime | None = None

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired.

        Returns:
            True if the token has expired, False otherwise.

        """
        return datetime.now(UTC) > self.expires_at

    @property
    def is_revoked(self) -> bool:
        """Check if the token has been revoked.

        Returns:
            True if the token has been revoked, False otherwise.

        """
        return self.revoked_at is not None

    @property
    def is_valid(self) -> bool:
        """Check if the token is valid (not expired and not revoked).

        Returns:
            True if the token is valid, False otherwise.

        """
        return not self.is_expired and not self.is_revoked


# Predefined roles using Python 3.13 patterns
ADMIN_ROLE = Role(
    name="REDACTED_LDAP_BIND_PASSWORD",
    permissions=frozenset(
        [
            "pipeline:create",
            "pipeline:read",
            "pipeline:update",
            "pipeline:delete",
            "plugin:install",
            "plugin:remove",
            "plugin:configure",
            "user:create",
            "user:read",
            "user:update",
            "user:delete",
            "system:REDACTED_LDAP_BIND_PASSWORD",
        ],
    ),
    description="System REDACTED_LDAP_BIND_PASSWORDistrator with full access",
)

OPERATOR_ROLE = Role(
    name="operator",
    permissions=frozenset(
        [
            "pipeline:read",
            "pipeline:update",
            "pipeline:execute",
            "plugin:read",
            "plugin:configure",
            "execution:create",
            "execution:read",
            "execution:cancel",
        ],
    ),
    description="Pipeline operator with execution permissions",
)

VIEWER_ROLE = Role(
    name="viewer",
    permissions=frozenset(["pipeline:read", "plugin:read", "execution:read"]),
    description="Read-only access to system resources",
)

# Rebuild models to resolve forward references after all definitions
User.model_rebuild()
TokenInfo.model_rebuild()
Permission.model_rebuild()
Role.model_rebuild()
