"""FLEXT Auth Application Services - Application layer orchestration.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import override

from flext_core import FlextDomainService, FlextModels, FlextResult

from flext_auth.constants import FlextAuthSemanticConstants
from flext_auth.entities import (
    FlextPermission,
    FlextRole,
    FlextUser,
    FlextUserRole,
    FlextUserStatus,
)
from flext_auth.models import FlextSession, FlextSessionStatus
from flext_auth.password import FlextPasswordService
from flext_auth.values import (
    FlextPlainPassword,
    FlextUserEmail,
    FlextUsername,
)


class FlextAuthenticationService(FlextDomainService[str]):
    """Service for authentication operations."""

    @override
    def execute(self) -> FlextResult[str]:
        """Execute service operation (required by FlextDomainService).

        This method is required by the abstract base class but services
        provide specific methods for their operations.

        Returns:
            FlextResult indicating this method should not be used directly

        """
        return FlextResult[str].fail(
            "Use specific service methods instead of execute",
        )

    def authenticate_user(
        self,
        username: str,
        password: str,
        users: dict[str, FlextUser],
    ) -> FlextResult[FlextUser]:
        """Authenticate a user using Railway-Oriented Programming pattern.

        Args:
            username: Username to authenticate
            password: Password to verify
            users: Dictionary of users (username -> user)

        Returns:
            FlextResult containing authenticated user

        """
        try:
            # REFACTORING: Railway-Oriented Programming - reduces 6 returns to 2
            return (
                self._get_user_from_dict(username, users)
                .flat_map(self._validate_user_status)
                .flat_map(lambda user: self._verify_user_password(user, password))
                .map(self._handle_successful_authentication)
            )
        except (KeyError, ValueError, AttributeError, TypeError) as e:
            return FlextResult[FlextUser].fail(f"Authentication failed: {e}")

    def _get_user_from_dict(
        self,
        username: str,
        users: dict[str, FlextUser],
    ) -> FlextResult[FlextUser]:
        """Get user from dictionary - Single Responsibility Principle."""
        user = users.get(username)
        if not user:
            return FlextResult[FlextUser].fail("User not found")
        return FlextResult[FlextUser].ok(user)

    def _validate_user_status(self, user: FlextUser) -> FlextResult[FlextUser]:
        """Validate user account status - Single Responsibility Principle."""
        if not user.is_active():
            return FlextResult[FlextUser].fail("User account is inactive")
        if user.is_locked():
            return FlextResult[FlextUser].fail("User account is locked")
        return FlextResult[FlextUser].ok(user)

    def _verify_user_password(
        self,
        user: FlextUser,
        password: str,
    ) -> FlextResult[FlextUser]:
        """Verify user password - Single Responsibility Principle."""
        password_service = FlextPasswordService()
        verify_result = password_service.verify_password(password, user.password_hash)

        if not verify_result.success or not verify_result.value:
            user.increment_failed_login()
            return FlextResult[FlextUser].fail("Invalid password")

        return FlextResult[FlextUser].ok(user)

    def _handle_successful_authentication(self, user: FlextUser) -> FlextUser:
        """Handle successful authentication - Single Responsibility Principle."""
        user.reset_failed_login()
        return user

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
    ) -> FlextResult[FlextUser]:
        """Create a new user.

        Args:
            username: Username
            email: Email address
            password: Plain text password

        Returns:
            FlextResult containing created user

        """
        try:
            # Validate input using value objects
            try:
                FlextUsername.model_validate({"value": username})
                FlextUserEmail.model_validate({"value": email})
                FlextPlainPassword.model_validate({"value": password})
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[FlextUser].fail(f"Input validation failed: {e}")

            password_service = FlextPasswordService()
            hash_result = password_service.hash_password(
                FlextPlainPassword.model_validate({"value": password}),
            )
            if not hash_result.success:
                return FlextResult[FlextUser].fail(
                    f"Password hashing failed: {hash_result.error}",
                )

            password_hash = hash_result.value.value if hash_result.value else ""

            user = FlextUser(
                id=FlextModels.EntityId(str(uuid.uuid4())),
                username=username,
                email=email,
                password_hash=password_hash,
                role=FlextUserRole.USER,
                status=FlextUserStatus.ACTIVE,
            )

            if not user.is_valid():
                return FlextResult[FlextUser].fail("Invalid user data")

            return FlextResult[FlextUser].ok(user)

        except (ValueError, TypeError, AttributeError, KeyError) as e:
            return FlextResult[FlextUser].fail(f"User creation failed: {e}")

    def change_password(
        self,
        user: FlextUser,
        old_password: str,
        new_password: str,
    ) -> FlextResult[bool]:
        """Change user password.

        Args:
            user: User to change password for
            old_password: Current password
            new_password: New password

        Returns:
            FlextResult indicating success

        """
        try:
            password_service = FlextPasswordService()

            # Verify current password
            verify_result = password_service.verify_password(
                old_password,
                user.password_hash,
            )
            if not verify_result.success or not verify_result.value:
                return FlextResult[bool].fail("Current password is incorrect")

            # Validate new password using value object
            try:
                FlextPlainPassword.model_validate({"value": new_password})
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[bool].fail(
                    f"New password validation failed: {e}",
                )

            # Hash new password
            hash_result = password_service.hash_password(
                FlextPlainPassword.model_validate({"value": new_password}),
            )
            if not hash_result.success:
                return FlextResult[bool].fail(
                    f"Password hashing failed: {hash_result.error}",
                )

            user.password_hash = hash_result.value.value if hash_result.value else ""
            return FlextResult[bool].ok(FlextAuthSemanticConstants.SUCCESS)

        except (ValueError, TypeError, AttributeError, KeyError) as e:
            return FlextResult[bool].fail(f"Password change failed: {e}")


class FlextSessionService(FlextDomainService[str]):
    """Service for session management operations."""

    @override
    def execute(self) -> FlextResult[str]:
        """Execute service operation (required by FlextDomainService).

        This method is required by the abstract base class but services
        provide specific methods for their operations.

        Returns:
            FlextResult indicating this method should not be used directly

        """
        return FlextResult[str].fail(
            "Use specific service methods instead of execute",
        )

    def create_session(
        self,
        user: FlextUser,
        expires_minutes: int = 60,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[FlextSession]:
        """Create a new session for user.

        Args:
            user: User to create session for
            expires_minutes: Session expiration in minutes
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            FlextResult containing created session

        """
        try:
            if not user.is_active():
                return FlextResult[FlextSession].fail(
                    "Cannot create session for inactive user",
                )

            session = FlextSession(
                id=FlextModels.EntityId(str(uuid.uuid4())),
                user_id=str(user.id),
                access_token=secrets.token_urlsafe(32),
                refresh_token=secrets.token_urlsafe(32),
                status=FlextSessionStatus.ACTIVE,
                ip_address=ip_address,
                user_agent=user_agent,
                expires_at=datetime.now(UTC) + timedelta(minutes=expires_minutes),
            )

            if not session.has_valid_data():
                return FlextResult[FlextSession].fail("Invalid session data")

            return FlextResult[FlextSession].ok(session)

        except (ValueError, TypeError, AttributeError, KeyError, OSError) as e:
            return FlextResult[FlextSession].fail(f"Session creation failed: {e}")

    def validate_session(self, session: FlextSession) -> FlextResult[bool]:
        """Validate a session.

        Args:
            session: Session to validate

        Returns:
            FlextResult indicating if session is valid

        """
        try:
            if not session.is_valid():
                return FlextResult[bool].fail("Session is not valid")

            return FlextResult[bool].ok(FlextAuthSemanticConstants.SUCCESS)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"Session validation failed: {e}")

    def revoke_session(self, session: FlextSession) -> FlextResult[bool]:
        """Revoke a session.

        Args:
            session: Session to revoke

        Returns:
            FlextResult indicating success

        """
        try:
            session.revoke()
            return FlextResult[bool].ok(FlextAuthSemanticConstants.SUCCESS)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"Session revocation failed: {e}")


class FlextAuthorizationService(FlextDomainService[str]):
    """Service for authorization operations."""

    @override
    def execute(self) -> FlextResult[str]:
        """Execute service operation (required by FlextDomainService).

        This method is required by the abstract base class but services
        provide specific methods for their operations.

        Returns:
            FlextResult indicating this method should not be used directly

        """
        return FlextResult[str].fail(
            "Use specific service methods instead of execute",
        )

    def check_permission(
        self,
        user: FlextUser,
        resource: str,
        action: str,
        roles: dict[str, FlextRole] | None = None,
    ) -> FlextResult[bool]:
        """Check if user has permission for resource and action.

        Args:
            user: User to check permissions for
            resource: Resource to check
            action: Action to check
            roles: Dictionary of roles (optional)

        Returns:
            FlextResult indicating if user has permission

        """
        try:
            # Admin users have all permissions
            if user.is_REDACTED_LDAP_BIND_PASSWORD():
                return FlextResult[bool].ok(FlextAuthSemanticConstants.SUCCESS)

            # If roles are provided, check role permissions
            if roles:
                user_role = roles.get(user.role)
                if user_role and user_role.has_permission(resource, action):
                    return FlextResult[bool].ok(FlextAuthSemanticConstants.SUCCESS)

            return FlextResult[bool].ok(FlextAuthSemanticConstants.FAILURE)

        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"Permission check failed: {e}")

    def create_role(
        self,
        name: str,
        description: str,
        permissions: list[FlextPermission] | None = None,
    ) -> FlextResult[FlextRole]:
        """Create a new role.

        Args:
            name: Role name
            description: Role description
            permissions: List of permissions

        Returns:
            FlextResult containing created role

        """
        try:
            if not name:
                return FlextResult[FlextRole].fail("Role name is required")

            role = FlextRole(
                id=FlextModels.EntityId(str(uuid.uuid4())),
                name=name,
                description=description,
                permissions=permissions or [],
            )

            if not role.is_valid():
                return FlextResult[FlextRole].fail("Invalid role data")

            return FlextResult[FlextRole].ok(role)

        except (ValueError, TypeError, AttributeError, KeyError) as e:
            return FlextResult[FlextRole].fail(f"Role creation failed: {e}")


# Alternative aliases
AuthenticationService = FlextAuthenticationService
SessionService = FlextSessionService
AuthorizationService = FlextAuthorizationService
