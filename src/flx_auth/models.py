"""Authentication models with Python 3.13 advanced patterns and Pydantic standardization."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from flx_core.domain.pydantic_base import DomainEntity, DomainValueObject
from pydantic import Field

if TYPE_CHECKING:
    from flx_core.domain.advanced_types import UserId

    from flx_auth.types import PermissionScope

# Python 3.13 type aliases for zero boilerplate
type PermissionSet = frozenset[str]
type RoleSet = frozenset[str]
type Claims = dict[str, Any]


class AuthStatus(Enum):
    """Authentication status enum.

    This enumeration defines the possible authentication states for a user
    account, including active, inactive, locked, suspended, and expired
    statuses for comprehensive access control.

    Note:
    ----
        Implements enterprise authentication state management patterns.

    """

    ACTIVE = auto()
    INACTIVE = auto()
    LOCKED = auto()
    SUSPENDED = auto()
    EXPIRED = auto()


class UserRoleEnum(Enum):
    """User role enum for access control."""

    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    USER = "user"
    SERVICE = "service"
    READONLY = "readonly"
    DEVELOPER = "developer"
    AUDITOR = "auditor"

    @classmethod
    def create(
        cls, name: str, permissions: list[Permission], description: str = ""
    ) -> Role:
        """Create a Role object from enum values."""
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
    action: str
    scope: PermissionScope
    description: str = ""

    @property
    def name(self) -> str:
        """Permission identifier."""
        return f"{self.resource}:{self.action}"

    @classmethod
    def create(
        cls, name: str, scope: PermissionScope, resource: str, description: str = ""
    ) -> Permission:
        """Create a new permission with proper naming."""
        # Extract action from name if it follows pattern "action_resource"
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
        """Return the role name as its ID."""
        return self.name

    def has_permission(self, permission: Permission) -> bool:
        """Check if role has permission."""
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
        """Check if user is active."""
        # Handle both enum and enum value due to Pydantic use_enum_values=True
        status_active = self.status in {AuthStatus.ACTIVE, AuthStatus.ACTIVE.value}
        return status_active and not self.is_locked

    @property
    def is_locked(self) -> bool:
        """Check if user is locked."""
        if self.locked_until:
            return datetime.now(UTC) < self.locked_until
        # Handle both enum and enum value due to Pydantic use_enum_values=True
        return self.status in {AuthStatus.LOCKED, AuthStatus.LOCKED.value}

    def has_role(self, role_name: str) -> bool:
        """Check if user has role."""
        return role_name in self.roles

    def add_role(self, role: Role) -> None:
        """Add role to user."""
        self.roles |= {role.name}
        self.updated_at = datetime.now(UTC)

    def get_active_roles(self) -> list[Role]:
        """Get all active roles for this user."""
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
        """Record successful login."""
        self.last_login = datetime.now(UTC)
        self.failed_attempts = 0
        self.locked_until = None

    def record_failed_attempt(
        self, lock_after: int = 5, lock_duration_minutes: int = 30
    ) -> None:
        """Record failed login attempt."""
        self.failed_attempts += 1
        if self.failed_attempts >= lock_after:
            self.locked_until = datetime.now(UTC).replace(
                minute=datetime.now(UTC).minute + lock_duration_minutes,
            )

    def to_claims(self) -> Claims:
        """Convert user to JWT claims."""
        # Handle enum serialization using try/except for better error handling
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

    token_id: UUID = Field(default_factory=uuid4)
    user_id: UserId = Field(default_factory=uuid4)
    token_type: str = Field(default="access", description="Token type identifier")
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    revoked_at: datetime | None = None

    @property
    def is_expired(self) -> bool:
        """Check if token is expired.

        This property determines if the token has exceeded its expiration
        time by comparing the current time with the token's expiration
        timestamp.

        Returns:
        -------
            bool: True if the token is expired, False otherwise.

        Note:
        ----
            Implements token lifecycle validation.

        """
        return datetime.now(UTC) > self.expires_at

    @property
    def is_revoked(self) -> bool:
        """Check if token is revoked.

        This property determines if the token has been explicitly revoked
        by checking for the presence of a revocation timestamp.

        Returns:
        -------
            bool: True if the token is revoked, False otherwise.

        Note:
        ----
            Implements token revocation validation.

        """
        return self.revoked_at is not None

    @property
    def is_valid(self) -> bool:
        """Check if token is valid.

        This property performs comprehensive token validation by ensuring
        the token is neither expired nor revoked. A token is only valid
        if it passes both checks.

        Returns:
        -------
            bool: True if the token is valid, False otherwise.

        Note:
        ----
            Implements complete token lifecycle validation.

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
