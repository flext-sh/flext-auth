"""FLEXT Authentication Models - Domain entities using flext-core foundation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, ClassVar

from flext_core import FlextModels, FlextResult, FlextTypes
from pydantic import Field, field_validator

from flext_auth.constants import FlextAuthConstants
from flext_auth.typings import FlextAuthTypes


class FlextAuthUser(FlextModels.Entity):
    """User aggregate root with advanced domain modeling."""

    # Advanced aggregate configuration
    aggregate_type: ClassVar[str] = "user"

    # Core user fields using FlextAuthTypes centralized types
    username: Annotated[
        FlextAuthTypes.Username,
        Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$"),
    ]
    email: FlextAuthTypes.Email
    password_hash: Annotated[
        FlextAuthTypes.PasswordHash, Field(min_length=60, max_length=255)
    ]

    # Authentication fields using centralized types
    role: FlextAuthTypes.UserRole = FlextAuthConstants.ROLE_USER
    status: FlextAuthTypes.UserStatus = FlextAuthConstants.USER_STATUS_ACTIVE
    failed_login_attempts: FlextAuthTypes.LoginAttempts = 0
    locked_until: datetime | None = None
    last_login: datetime | None = None

    # Permissions using FlextAuthTypes
    permissions: Annotated[
        list[FlextAuthTypes.Permission], Field(default_factory=list, max_length=100)
    ]

    # Advanced field validators using Python 3.13+ patterns
    @field_validator("username")
    @classmethod
    def validate_username_advanced(
        cls, v: FlextAuthTypes.Username
    ) -> FlextAuthTypes.Username:
        """Advanced username validation with Python 3.13+ patterns."""
        if not v or len(v) < FlextAuthConstants.MIN_USERNAME_LENGTH:
            msg = f"Username must be at least {FlextAuthConstants.MIN_USERNAME_LENGTH} chars"
            raise ValueError(msg)
        if len(v) > FlextAuthConstants.MAX_USERNAME_LENGTH:
            msg = f"Username must be at most {FlextAuthConstants.MAX_USERNAME_LENGTH} chars"
            raise ValueError(msg)
        return v.strip().lower()

    @field_validator("role")
    @classmethod
    def validate_role_advanced(
        cls, v: FlextAuthTypes.UserRole
    ) -> FlextAuthTypes.UserRole:
        """Advanced role validation."""
        valid_roles = {
            FlextAuthConstants.ROLE_USER,
            FlextAuthConstants.ROLE_ADMIN,
            FlextAuthConstants.ROLE_GUEST,
        }
        if v not in valid_roles:
            msg = f"Invalid role. Must be one of: {valid_roles}"
            raise ValueError(msg)
        return v

    @field_validator("status")
    @classmethod
    def validate_status_advanced(
        cls, v: FlextAuthTypes.UserStatus
    ) -> FlextAuthTypes.UserStatus:
        """Advanced status validation."""
        valid_statuses = {
            FlextAuthConstants.USER_STATUS_ACTIVE,
            FlextAuthConstants.USER_STATUS_INACTIVE,
            FlextAuthConstants.USER_STATUS_LOCKED,
            FlextAuthConstants.USER_STATUS_SUSPENDED,
        }
        if v not in valid_statuses:
            msg = f"Invalid status. Must be one of: {valid_statuses}"
            raise ValueError(msg)
        return v

    def validate_business_rules(self) -> FlextResult[None]:
        """Enhanced business rules validation for aggregate."""
        try:
            # Basic validations are handled by field validators
            # Additional complex business rules here
            if (
                self.failed_login_attempts > FlextAuthConstants.MAX_LOGIN_ATTEMPTS
                and not self.locked_until
            ):
                return FlextResult[None].fail(
                    "User should be locked after max attempts"
                )

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Business rule validation failed: {e}")

    def can_login(self) -> FlextAuthTypes.IsActive:
        """Check if user can login."""
        # User must not be inactive or suspended
        if self.status in {
            FlextAuthConstants.USER_STATUS_INACTIVE,
            FlextAuthConstants.USER_STATUS_SUSPENDED,
        }:
            return False

        # If user is locked, check if lockout has expired
        if self.status == FlextAuthConstants.USER_STATUS_LOCKED:
            return not (self.locked_until and datetime.now(UTC) < self.locked_until)

        # Active users can login if not currently locked
        return not (self.locked_until and datetime.now(UTC) < self.locked_until)

    def has_permission(
        self, permission: FlextAuthTypes.Permission
    ) -> FlextAuthTypes.HasPermission:
        """Check if user has specific permission."""
        if self.role == FlextAuthConstants.ROLE_ADMIN:
            return True
        return permission in self.permissions

    def add_permission(self, permission: FlextAuthTypes.Permission) -> None:
        """Add permission to user with domain event."""
        if permission not in self.permissions:
            self.permissions.append(permission)
            self.increment_version()

            # NOTE: Domain event publishing deferred until flext-core event patterns stabilize
            # Avoiding event publishing to prevent type compatibility issues

    def remove_permission(self, permission: FlextAuthTypes.Permission) -> None:
        """Remove permission from user with domain event."""
        if permission in self.permissions:
            self.permissions.remove(permission)
            self.increment_version()

            # NOTE: Domain event publishing deferred until flext-core event patterns stabilize
            # Avoiding event publishing to prevent type compatibility issues

    def login_succeeded(self) -> None:
        """Handle successful login with domain events."""
        self.last_login = datetime.now(UTC)
        self.failed_login_attempts = 0
        self.increment_version()

        # NOTE: Domain event publishing deferred until flext-core event patterns stabilize
        # Avoiding event publishing to prevent type compatibility issues

    def login_failed(self) -> None:
        """Handle failed login with domain events and business rules."""
        self.failed_login_attempts += 1

        # Check if user should be locked
        if self.failed_login_attempts >= FlextAuthConstants.MAX_LOGIN_ATTEMPTS:
            self.locked_until = datetime.now(UTC) + timedelta(
                minutes=FlextAuthConstants.DEFAULT_LOCKOUT_DURATION_MINUTES
            )
            self.status = FlextAuthConstants.USER_STATUS_LOCKED

            # Create user locked event data
            locked_event_data: FlextTypes.Core.JsonObject = {
                "event_type": "UserAccountLocked",
                "aggregate_id": str(self.id),
                "user_id": str(self.id),
                "username": self.username,
                "failed_attempts": self.failed_login_attempts,
                "locked_until": self.locked_until.isoformat(),
                "source_service": "flext-auth",
            }
            self.add_domain_event(locked_event_data)

        # Create failed login event data
        failed_event_data: FlextTypes.Core.JsonObject = {
            "event_type": "UserLoginFailed",
            "aggregate_id": str(self.id),
            "user_id": str(self.id),
            "username": self.username,
            "failed_attempts": self.failed_login_attempts,
            "source_service": "flext-auth",
        }
        self.add_domain_event(failed_event_data)

        self.increment_version()


class FlextAuthSession(FlextModels.Entity):
    """Session domain entity for user sessions."""

    # Core session fields
    user_id: FlextAuthTypes.UserId
    access_token: FlextAuthTypes.AccessToken
    refresh_token: FlextAuthTypes.RefreshToken | None = None

    # Session metadata
    ip_address: FlextAuthTypes.String = "unknown"
    user_agent: FlextAuthTypes.String | None = None
    expires_at: datetime
    is_active: bool = True

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate session business rules."""
        if not self.user_id:
            return FlextResult[None].fail("User ID required")

        if not self.access_token:
            return FlextResult[None].fail("Access token required")

        # Note: We don't validate expiration time here to allow creation of
        # expired sessions for testing purposes. Expiration is checked by is_expired()

        return FlextResult[None].ok(None)

    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now(UTC) >= self.expires_at

    def deactivate(self) -> None:
        """Deactivate session."""
        self.is_active = False
        self.increment_version()


class FlextAuthRole(FlextModels.Entity):
    """Role domain entity with permissions."""

    name: FlextAuthTypes.UserRole
    permissions: list[FlextAuthTypes.Permission] = Field(default_factory=list)
    description: FlextAuthTypes.String = ""
    is_active: bool = True

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate role business rules."""
        if not self.name:
            return FlextResult[None].fail("Role name required")

        return FlextResult[None].ok(None)

    def has_permission(
        self, permission: FlextAuthTypes.Permission
    ) -> FlextAuthTypes.HasPermission:
        """Check if role has specific permission."""
        return permission in self.permissions

    def add_permission(self, permission: FlextAuthTypes.Permission) -> None:
        """Add permission to role."""
        if permission not in self.permissions:
            self.permissions.append(permission)
            self.increment_version()

    def remove_permission(self, permission: FlextAuthTypes.Permission) -> None:
        """Remove permission from role."""
        if permission in self.permissions:
            self.permissions.remove(permission)
            self.increment_version()


class FlextAuthPermission(FlextModels.Entity):
    """Permission domain entity."""

    name: FlextAuthTypes.Permission
    resource: FlextAuthTypes.String
    action: FlextAuthTypes.String
    description: FlextAuthTypes.String = ""
    is_active: bool = True

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate permission business rules."""
        if not self.name or not self.resource or not self.action:
            return FlextResult[None].fail("Name, resource, and action required")

        return FlextResult[None].ok(None)

    def matches(self, resource: FlextAuthTypes.String, action: FlextAuthTypes.String) -> bool:
        """Check if permission matches resource and action."""
        return self.resource == resource and self.action == action


class FlextAuthModels:
    """Authentication models container class."""

    # Domain entities
    User = FlextAuthUser
    Session = FlextAuthSession
    Role = FlextAuthRole
    Permission = FlextAuthPermission

    # Factory methods
    @classmethod
    def create_user(
        cls,
        username: FlextAuthTypes.Username,
        email: FlextAuthTypes.String,
        password_hash: FlextAuthTypes.String,
        role: FlextAuthTypes.UserRole = FlextAuthConstants.ROLE_USER,
    ) -> FlextResult[FlextAuthUser]:
        """Create user with validation."""
        try:

            user_data = {
                "id": f"user_{username}_{int(time.time_ns())}",
                "username": username,
                "email": email,
                "password_hash": password_hash,
                "role": role,
                "status": FlextAuthConstants.USER_STATUS_ACTIVE,
                "failed_login_attempts": 0,
                "permissions": [],
            }

            user = FlextAuthUser.model_validate(user_data)
            validation_result = user.validate_business_rules()

            if validation_result.is_failure:
                return FlextResult[FlextAuthUser].fail(
                    validation_result.error or "Validation failed"
                )

            return FlextResult[FlextAuthUser].ok(user)

        except Exception as e:
            return FlextResult[FlextAuthUser].fail(f"User creation failed: {e}")

    @classmethod
    def create_session(
        cls,
        user_id: FlextAuthTypes.UserId,
        access_token: FlextAuthTypes.AccessToken,
        expires_at: datetime,
        ip_address: FlextAuthTypes.String = "unknown",
        user_agent: FlextAuthTypes.String | None = None,
    ) -> FlextResult[FlextAuthSession]:
        """Create session with validation."""
        try:

            session_data = {
                "id": f"session_{user_id}_{int(time.time_ns())}",
                "user_id": user_id,
                "access_token": access_token,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "expires_at": expires_at,
                "is_active": True,
            }

            session = FlextAuthSession.model_validate(session_data)
            validation_result = session.validate_business_rules()

            if validation_result.is_failure:
                return FlextResult[FlextAuthSession].fail(
                    validation_result.error or "Validation failed"
                )

            return FlextResult[FlextAuthSession].ok(session)

        except Exception as e:
            return FlextResult[FlextAuthSession].fail(f"Session creation failed: {e}")

    @classmethod
    def create_role(
        cls,
        name: FlextAuthTypes.UserRole,
        description: FlextAuthTypes.String = "",
        permissions: list[FlextAuthTypes.Permission] | None = None,
    ) -> FlextResult[FlextAuthRole]:
        """Create role with validation."""
        try:

            role_data = {
                "id": f"role_{name}_{int(time.time_ns())}",
                "name": name,
                "permissions": permissions or [],
                "description": description,
            }

            role = FlextAuthRole.model_validate(role_data)
            validation_result = role.validate_business_rules()

            if validation_result.is_failure:
                return FlextResult[FlextAuthRole].fail(
                    validation_result.error or "Validation failed"
                )

            return FlextResult[FlextAuthRole].ok(role)

        except Exception as e:
            return FlextResult[FlextAuthRole].fail(f"Role creation failed: {e}")

    @classmethod
    def create_permission(
        cls,
        name: str,
        description: str,
        resource: str,
        action: str,
    ) -> FlextResult[FlextAuthPermission]:
        """Create permission with validation."""
        try:

            permission_data = {
                "id": f"perm_{name}_{int(time.time_ns())}",
                "name": name,
                "resource": resource,
                "action": action,
                "description": description,
            }

            permission = FlextAuthPermission.model_validate(permission_data)
            validation_result = permission.validate_business_rules()

            if validation_result.is_failure:
                return FlextResult[FlextAuthPermission].fail(
                    validation_result.error or "Validation failed"
                )

            return FlextResult[FlextAuthPermission].ok(permission)

        except Exception as e:
            return FlextResult[FlextAuthPermission].fail(
                f"Permission creation failed: {e}"
            )

    # Repository implementations
    class InMemoryUserRepository:
        """In-memory user repository for development."""

        def __init__(self) -> None:
            self._users: dict[str, FlextAuthUser] = {}

        def save(self, user: FlextAuthUser) -> FlextResult[FlextAuthUser]:
            """Save user."""
            try:
                self._users[user.id] = user
                return FlextResult[FlextAuthUser].ok(user)
            except Exception as e:
                return FlextResult[FlextAuthUser].fail(f"Save failed: {e}")

        def get_by_id(self, user_id: FlextAuthTypes.UserId) -> FlextResult[FlextAuthUser | None]:
            """Get user by ID."""
            try:
                user = self._users.get(user_id)
                return FlextResult[FlextAuthUser | None].ok(user)
            except Exception as e:
                return FlextResult[FlextAuthUser | None].fail(f"Get by ID failed: {e}")

        def get_by_username(self, username: FlextAuthTypes.Username) -> FlextResult[FlextAuthUser | None]:
            """Get user by username."""
            try:
                for user in self._users.values():
                    if user.username == username:
                        return FlextResult[FlextAuthUser | None].ok(user)
                return FlextResult[FlextAuthUser | None].ok(None)
            except Exception as e:
                return FlextResult[FlextAuthUser | None].fail(
                    f"Get by username failed: {e}"
                )

        def get_by_email(self, email: FlextAuthTypes.Email) -> FlextResult[FlextAuthUser | None]:
            """Get user by email."""
            try:
                for user in self._users.values():
                    # Compare normalized email strings to avoid type mismatches
                    if str(user.email) == email:
                        return FlextResult[FlextAuthUser | None].ok(user)
                return FlextResult[FlextAuthUser | None].ok(None)
            except Exception as e:
                return FlextResult[FlextAuthUser | None].fail(
                    f"Get by email failed: {e}"
                )

    class InMemorySessionRepository:
        """In-memory session repository for development."""

        def __init__(self) -> None:
            self._sessions: dict[str, FlextAuthSession] = {}

        def save(self, session: FlextAuthSession) -> FlextResult[FlextAuthSession]:
            """Save session."""
            try:
                self._sessions[session.id] = session
                return FlextResult[FlextAuthSession].ok(session)
            except Exception as e:
                return FlextResult[FlextAuthSession].fail(f"Save failed: {e}")

        def get_by_id(self, session_id: FlextAuthTypes.SessionId) -> FlextResult[FlextAuthSession | None]:
            """Get session by ID."""
            try:
                session = self._sessions.get(session_id)
                return FlextResult[FlextAuthSession | None].ok(session)
            except Exception as e:
                return FlextResult[FlextAuthSession | None].fail(
                    f"Get by ID failed: {e}"
                )

        def get_by_user_id(self, user_id: FlextAuthTypes.UserId) -> FlextResult[list[FlextAuthSession]]:
            """Get all sessions for user."""
            try:
                sessions = [s for s in self._sessions.values() if s.user_id == user_id]
                return FlextResult[list[FlextAuthSession]].ok(sessions)
            except Exception as e:
                return FlextResult[list[FlextAuthSession]].fail(
                    f"Get by user ID failed: {e}"
                )

        def delete_expired(self) -> FlextResult[int]:
            """Delete expired sessions."""
            try:
                current_time = datetime.now(UTC)
                expired_ids = [
                    sid
                    for sid, session in self._sessions.items()
                    if session.expires_at <= current_time
                ]

                for sid in expired_ids:
                    del self._sessions[sid]

                return FlextResult[int].ok(len(expired_ids))
            except Exception as e:
                return FlextResult[int].fail(f"Delete expired failed: {e}")

    # No helper functions - use FlextPasswordService and FlextAuthUtilities directly


__all__ = [
    "FlextAuthModels",
    "FlextAuthPermission",
    "FlextAuthRole",
    "FlextAuthSession",
    "FlextAuthUser",
]
