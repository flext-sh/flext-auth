"""FLEXT Auth Models - SINGLE CONSOLIDATED CLASS following FLEXT patterns.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

FLEXT REFACTORING: Consolidated ALL model definitions into single FlextAuthModels class
following FLEXT architectural standards. Individual models available as nested classes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, override

from flext_core import (
    FlextEntity,
    FlextModel,
    FlextResult,
    FlextTimestamp,
)
from pydantic import Field

# Direct imports to avoid circular dependencies
from .entities import (
    FlextEmailVerificationToken,
    FlextPasswordResetToken,
    FlextUser,
    FlextUserRole,
    FlextUserStatus,
)
from .flext_auth_types import UserRepositoryType
from .values import (
    FlextHashedPassword,
    FlextJWTClaims,
    FlextPlainPassword,
    FlextSecurityContext,
    FlextUserEmail,
    FlextUsername,
)

# =============================================================================
# SINGLE CONSOLIDATED CLASS - FLEXT ARCHITECTURAL PATTERN
# =============================================================================


class FlextAuthModels(FlextModel):
    """Single consolidated class containing ALL authentication models.

    FLEXT REFACTORING: Consolidates ALL model definitions into one class following
    FLEXT architectural standards. Individual models available as nested classes
    for organization while maintaining single entry point.

    Usage:
        models = FlextAuthModels()
        session = models.Session(...)
        permission = models.Permission(...)
    """

    # =============================================================================
    # CONSTANTS AND ENUMS - Nested inside consolidated class
    # =============================================================================

    # Constants for magic numbers - ClassVar to exclude from Pydantic fields
    MIN_USERNAME_LENGTH: ClassVar[int] = 3
    MAX_USERNAME_LENGTH: ClassVar[int] = 50
    MIN_PASSWORD_LENGTH: ClassVar[int] = 8
    MAX_PASSWORD_LENGTH: ClassVar[int] = 128
    MAX_NAME_LENGTH: ClassVar[int] = 100
    MAX_DESCRIPTION_LENGTH: ClassVar[int] = 500
    MAX_SESSION_ID_LENGTH: ClassVar[int] = 32
    MIN_TOKEN_LENGTH: ClassVar[int] = 32
    MIN_BCRYPT_HASH_LENGTH: ClassVar[int] = 56  # Minimum bcrypt hash length for production
    MIN_AUTH_TOKEN_LENGTH: ClassVar[int] = 10
    MIN_REFRESH_TOKEN_LENGTH: ClassVar[int] = 32
    MIN_SESSION_TOKEN_LENGTH: ClassVar[int] = 16
    MAX_USER_AGENT_LENGTH: ClassVar[int] = 500
    MIN_PASSWORD_RESET_TOKEN_LENGTH: ClassVar[int] = 32
    MIN_EMAIL_VERIFICATION_TOKEN_LENGTH: ClassVar[int] = 32

    class SessionStatus(StrEnum):
        """Session status enum nested inside consolidated class."""

        ACTIVE = "active"
        EXPIRED = "expired"
        REVOKED = "revoked"

    # =============================================================================
    # DOMAIN ENTITIES - Rich business objects nested inside consolidated class
    # =============================================================================

    class Session(FlextEntity):
        """User session entity nested inside consolidated class."""

        # id is inherited from FlextEntity - no need to redefine
        user_id: str = Field(..., description="User ID owning this session")
        access_token: str = Field(..., description="JWT access token")
        refresh_token: str | None = Field(default=None, description="JWT refresh token")
        status: FlextAuthModels.SessionStatus = Field(
            default="active",
            description="Session status",
        )
        ip_address: str | None = Field(default=None, description="Client IP address")
        user_agent: str | None = Field(default=None, description="Client user agent")
        expires_at: datetime = Field(..., description="Session expiration time")
        created_at: FlextTimestamp = Field(default_factory=FlextTimestamp.now)
        last_accessed: datetime = Field(default_factory=lambda: datetime.now(UTC))

        def is_valid(self) -> bool:
            """Check if session is valid (active and not expired)."""
            if self.status != "active":
                return False
            return datetime.now(UTC) < self.expires_at

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules required by FlextEntity abstract method."""
            if not self.id:
                msg = "Session ID cannot be empty"
                raise ValueError(msg)
            if not self.user_id:
                msg = "User ID cannot be empty"
                raise ValueError(msg)
            if not self.access_token:
                msg = "Access token cannot be empty"
                raise ValueError(msg)
            if self.expires_at <= datetime.now(UTC):
                msg = "Session expiration must be in the future"
                raise ValueError(msg)
            return FlextResult[None].ok(None)

    class Permission(FlextEntity):
        """Permission entity nested inside consolidated class."""

        # id is inherited from FlextEntity - no need to redefine
        name: str = Field(..., description="Permission name")
        description: str = Field(..., description="Permission description")
        resource: str = Field(..., description="Resource this permission applies to")
        action: str = Field(..., description="Action allowed by this permission")

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate permission business rules and business invariants."""
            if not self.id:
                msg = "Permission ID cannot be empty"
                raise ValueError(msg)
            if not self.name:
                msg = "Permission name cannot be empty"
                raise ValueError(msg)
            if not self.resource:
                msg = "Permission resource cannot be empty"
                raise ValueError(msg)
            if not self.action:
                msg = "Permission action cannot be empty"
                raise ValueError(msg)
            return FlextResult[None].ok(None)

    class Role(FlextEntity):
        """Role entity with permissions nested inside consolidated class."""

        # id is inherited from FlextEntity - no need to redefine
        name: str = Field(..., description="Role name")
        description: str = Field(..., description="Role description")
        permissions: list[FlextAuthModels.Permission] = Field(
            default_factory=list,
            description="Role permissions",
        )
        is_system_role: bool = Field(
            default=False,
            description="Whether this is a system role",
        )
        created_at: FlextTimestamp = Field(default_factory=FlextTimestamp.now)

        def has_permission(self, resource: str, action: str) -> bool:
            """Check if role has specific permission."""
            return any(
                p.resource == resource and p.action == action for p in self.permissions
            )

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules required by FlextEntity abstract method."""
            if not self.id:
                return FlextResult[None].fail("Role ID cannot be empty")
            if not self.name:
                return FlextResult[None].fail("Role name cannot be empty")
            if not self.description:
                return FlextResult[None].fail("Role description cannot be empty")
            if len(self.name) > FlextAuthModels.MAX_NAME_LENGTH:
                return FlextResult[None].fail("Role name must be at most 100 characters")
            if len(self.description) > FlextAuthModels.MAX_DESCRIPTION_LENGTH:
                return FlextResult[None].fail(
                    "Role description must be at most 500 characters",
                )
            return FlextResult[None].ok(None)

    # =============================================================================
    # BACKWARD COMPATIBILITY PROPERTIES - Legacy access patterns
    # =============================================================================

    @property
    def FlextSession(self) -> type[FlextAuthModels.Session]:  # noqa: N802
        """Legacy compatibility property."""
        return self.Session

    @property
    def FlextPermission(self) -> type[FlextAuthModels.Permission]:  # noqa: N802
        """Legacy compatibility property."""
        return self.Permission

    @property
    def FlextRole(self) -> type[FlextAuthModels.Role]:  # noqa: N802
        """Legacy compatibility property."""
        return self.Role

    @property
    def FlextSessionStatus(self) -> type[FlextAuthModels.SessionStatus]:  # noqa: N802
        """Legacy compatibility property."""
        return self.SessionStatus


# =============================================================================
# REPOSITORY PATTERNS - Abstract data access
# =============================================================================

# ✅ CORRECT - Use centralized repository protocol from types.py
# Replaces duplicate protocol definition with import from centralized types
UserRepository = UserRepositoryType


class InMemoryUserRepository(UserRepository):
    """In-memory user repository for development and demonstrations."""

    def __init__(self) -> None:
        """Initialize empty user storage."""
        self._users: dict[str, FlextUser] = {}
        self._username_index: dict[str, str] = {}  # username -> user_id
        self._email_index: dict[str, str] = {}  # email -> user_id

    @override
    def save(self, entity: FlextUser) -> FlextResult[FlextUser]:
        """Save user to memory (sync for flext-core compliance)."""
        try:
            # Check for username conflicts
            existing_username = self._username_index.get(entity.username.lower())
            if existing_username and existing_username != entity.id:
                return FlextResult[FlextUser].fail(
                    f"Username '{entity.username}' already exists",
                )

            # Check for email conflicts
            existing_email = self._email_index.get(str(entity.email).lower())
            if existing_email and existing_email != entity.id:
                return FlextResult[FlextUser].fail(
                    f"Email '{entity.email}' already exists",
                )

            # Create user with updated timestamp (entities are immutable)
            updated_user = FlextUser(
                id=entity.id,
                username=entity.username,
                email=entity.email,
                password_hash=entity.password_hash,
                role=entity.role,
                status=entity.status,
                failed_login_attempts=entity.failed_login_attempts,
                locked_until=entity.locked_until,
                last_login=entity.last_login,
                created_at=entity.created_at,
                updated_at=FlextTimestamp.now(),
            )

            # Save user
            self._users[str(updated_user.id)] = updated_user
            self._username_index[updated_user.username.lower()] = str(updated_user.id)
            self._email_index[str(updated_user.email).lower()] = str(updated_user.id)

            return FlextResult[FlextUser].ok(updated_user)

        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextUser].fail(f"Failed to save user: {e}")

    @override
    def get_by_id(self, entity_id: str) -> FlextResult[FlextUser | None]:
        """Get user by ID (sync for flext-core compliance)."""
        try:
            user = self._users.get(entity_id)
            return FlextResult[FlextUser | None].ok(user)
        except (KeyError, ValueError, TypeError) as e:
            return FlextResult[FlextUser | None].fail(f"Failed to get user by ID: {e}")

    @override
    def get_by_username(self, username: str) -> FlextResult[FlextUser | None]:
        """Get user by username (sync for flext-core compliance)."""
        try:
            user_id = self._username_index.get(username.lower())
            if not user_id:
                return FlextResult[FlextUser | None].ok(None)

            user = self._users.get(user_id)
            return FlextResult[FlextUser | None].ok(user)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextUser | None].fail(
                f"Failed to get user by username: {e}",
            )

    @override
    def get_by_email(self, email: str) -> FlextResult[FlextUser | None]:
        """Get user by email (sync for flext-core compliance)."""
        try:
            user_id = self._email_index.get(email.lower())
            if not user_id:
                return FlextResult[FlextUser | None].ok(None)

            user = self._users.get(user_id)
            return FlextResult[FlextUser | None].ok(user)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextUser | None].fail(
                f"Failed to get user by email: {e}",
            )

    @override
    def delete(self, entity_id: str) -> FlextResult[None]:
        """Delete user from memory (sync for flext-core compliance)."""
        try:
            user = self._users.get(entity_id)
            if not user:
                return FlextResult[None].fail("User not found")

            # Remove from indexes
            self._username_index.pop(user.username.lower(), None)
            self._email_index.pop(str(user.email).lower(), None)

            # Remove user
            del self._users[entity_id]

            return FlextResult[None].ok(None)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to delete user: {e}")

    @override
    def find_all(self) -> FlextResult[list[FlextUser]]:
        """Find all users (sync for flext-core compliance)."""
        try:
            users = list(self._users.values())
            # Sort by created_at (newest first)
            users.sort(key=lambda u: u.created_at.root, reverse=True)
            return FlextResult[list[FlextUser]].ok(users)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[FlextUser]].fail(f"Failed to find all users: {e}")


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def convert_user_to_dict(user: FlextUser) -> dict[str, object]:
    """Convert FlextUser to dictionary."""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "status": user.status,
        "created_at": str(user.created_at),
        "updated_at": str(user.updated_at),
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }


# =============================================================================
# EXPORTS - Clean models API
# =============================================================================

# =============================================================================
# BACKWARD COMPATIBILITY - Legacy class exports
# =============================================================================

# Create backward compatibility aliases for legacy imports
FlextSession = FlextAuthModels.Session
FlextPermission = FlextAuthModels.Permission
FlextRole = FlextAuthModels.Role
FlextSessionStatus = FlextAuthModels.SessionStatus


# Add missing legacy classes that are imported by other modules
class FlextLoginAttempt(FlextEntity):
    """Login attempt tracking - legacy compatibility class."""

    username: str = Field(..., description="Username attempted")
    ip_address: str = Field(..., description="Client IP address")
    user_agent: str | None = Field(default=None, description="Client user agent")
    success: bool = Field(..., description="Whether login was successful")
    failure_reason: str | None = Field(default=None, description="Reason for failure")
    attempted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules required by FlextEntity abstract method."""
        if not self.id:
            msg = "Login attempt ID cannot be empty"
            raise ValueError(msg)
        if not self.username:
            msg = "Username cannot be empty"
            raise ValueError(msg)
        if not self.ip_address:
            msg = "IP address cannot be empty"
            raise ValueError(msg)
        return FlextResult[None].ok(None)


# Export constants for backward compatibility
MIN_USERNAME_LENGTH = FlextAuthModels.MIN_USERNAME_LENGTH
MAX_USERNAME_LENGTH = FlextAuthModels.MAX_USERNAME_LENGTH
MIN_PASSWORD_LENGTH = FlextAuthModels.MIN_PASSWORD_LENGTH
MAX_PASSWORD_LENGTH = FlextAuthModels.MAX_PASSWORD_LENGTH
MAX_NAME_LENGTH = FlextAuthModels.MAX_NAME_LENGTH
MAX_DESCRIPTION_LENGTH = FlextAuthModels.MAX_DESCRIPTION_LENGTH
MAX_SESSION_ID_LENGTH = FlextAuthModels.MAX_SESSION_ID_LENGTH
MIN_TOKEN_LENGTH = FlextAuthModels.MIN_TOKEN_LENGTH
MIN_BCRYPT_HASH_LENGTH = FlextAuthModels.MIN_BCRYPT_HASH_LENGTH

__all__: list[str] = [
    "MAX_DESCRIPTION_LENGTH",
    "MAX_NAME_LENGTH",
    "MAX_PASSWORD_LENGTH",
    "MAX_SESSION_ID_LENGTH",
    "MAX_USERNAME_LENGTH",
    "MIN_BCRYPT_HASH_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "MIN_TOKEN_LENGTH",
    # Legacy constant exports for backward compatibility
    "MIN_USERNAME_LENGTH",
    # CONSOLIDATED CLASS - FLEXT Pattern (main export)
    "FlextAuthModels",
    # Legacy exports for backward compatibility
    "FlextEmailVerificationToken",
    "FlextHashedPassword",
    "FlextJWTClaims",
    "FlextLoginAttempt",
    "FlextPasswordResetToken",
    "FlextPermission",
    "FlextPlainPassword",
    "FlextRole",
    "FlextSecurityContext",
    # Legacy class exports for backward compatibility
    "FlextSession",
    "FlextSessionStatus",
    # Domain Entities
    "FlextUser",
    "FlextUserEmail",
    "FlextUserRole",
    # Enums
    "FlextUserStatus",
    # Value Objects
    "FlextUsername",
    "InMemoryUserRepository",
    # Repository Patterns
    "UserRepository",
    # Utilities
    "convert_user_to_dict",
]
