"""FLEXT Auth Application Services - Authentication and authorization services.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

Application services for authentication and authorization operations.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from flext_core import FlextDomainService, FlextResult

from flext_auth.domain.entities import (
    FlextRole,
    FlextSession,
    FlextSessionStatus,
    FlextUser,
    FlextUserRole,
    FlextUserStatus,
)
from flext_auth.domain.value_objects import (
    FlextPlainPassword,
    FlextUserEmail,
    FlextUsername,
)
from flext_auth.services.password_service import FlextPasswordService

if TYPE_CHECKING:
    from flext_auth.domain.entities import (
        FlextPermission,
    )


class FlextAuthenticationService(FlextDomainService):
    """Service for authentication operations."""

    def execute(self) -> FlextResult[str]:
        """Execute service operation (required by FlextDomainService).

        This method is required by the abstract base class but services
        provide specific methods for their operations.

        Returns:
            FlextResult indicating this method should not be used directly

        """
        return FlextResult.fail(
            "Use specific service methods instead of execute",
        )

    def authenticate_user(
        self,
        username: str,
        password: str,
        users: dict[str, FlextUser],
    ) -> FlextResult[FlextUser]:
        """Authenticate a user.

        Args:
            username: Username to authenticate
            password: Password to verify
            users: Dictionary of users (username -> user)

        Returns:
            FlextResult containing authenticated user

        """
        try:
            user = users.get(username)
            if not user:
                return FlextResult.fail("User not found")

            if not user.is_active():
                return FlextResult.fail("User account is inactive")

            if user.is_locked():
                return FlextResult.fail("User account is locked")

            password_service = FlextPasswordService()
            verify_result = password_service.verify_password(
                password,
                user.password_hash,
            )
            if not verify_result.is_success or not verify_result.data:
                user.increment_failed_login()
                return FlextResult.fail("Invalid password")

            user.reset_failed_login()
            return FlextResult.ok(user)

        except (KeyError, ValueError, AttributeError, TypeError) as e:
            return FlextResult.fail(f"Authentication failed: {e}")

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
                FlextUsername(value=username)
                FlextUserEmail(value=email)
                FlextPlainPassword(value=password)
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult.fail(f"Input validation failed: {e}")

            password_service = FlextPasswordService()
            hash_result = password_service.hash_password(
                FlextPlainPassword(value=password),
            )
            if not hash_result.is_success:
                return FlextResult.fail(
                    f"Password hashing failed: {hash_result.error}",
                )

            password_hash = hash_result.data.value if hash_result.data else ""

            user = FlextUser(
                id=str(uuid.uuid4()),
                username=username,
                email=email,
                password_hash=password_hash,
                role=FlextUserRole.USER,
                status=FlextUserStatus.ACTIVE,
            )

            if not user.is_valid():
                return FlextResult.fail("Invalid user data")

            return FlextResult.ok(user)

        except (ValueError, TypeError, AttributeError, KeyError) as e:
            return FlextResult.fail(f"User creation failed: {e}")

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
            if not verify_result.is_success or not verify_result.data:
                return FlextResult.fail("Current password is incorrect")

            # Validate new password using value object
            try:
                FlextPlainPassword(value=new_password)
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult.fail(
                    f"New password validation failed: {e}",
                )

            # Hash new password
            hash_result = password_service.hash_password(
                FlextPlainPassword(value=new_password),
            )
            if not hash_result.is_success:
                return FlextResult.fail(
                    f"Password hashing failed: {hash_result.error}",
                )

            user.password_hash = hash_result.data.value if hash_result.data else ""
            return FlextResult.ok(True)

        except (ValueError, TypeError, AttributeError, KeyError) as e:
            return FlextResult(success=False, error=f"Password change failed: {e}")


class FlextSessionService(FlextDomainService):
    """Service for session management operations."""

    def execute(self) -> FlextResult[str]:
        """Execute service operation (required by FlextDomainService).

        This method is required by the abstract base class but services
        provide specific methods for their operations.

        Returns:
            FlextResult indicating this method should not be used directly

        """
        return FlextResult.fail(
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
                return FlextResult(
                    success=False,
                    error="Cannot create session for inactive user",
                )

            session = FlextSession(
                id=str(uuid.uuid4()),
                user_id=str(user.id),
                access_token=secrets.token_urlsafe(32),
                refresh_token=secrets.token_urlsafe(32),
                status=FlextSessionStatus.ACTIVE,
                ip_address=ip_address,
                user_agent=user_agent,
                expires_at=datetime.now(UTC) + timedelta(minutes=expires_minutes),
            )

            if not session.has_valid_data():
                return FlextResult(success=False, error="Invalid session data")

            return FlextResult(success=True, data=session)

        except (ValueError, TypeError, AttributeError, KeyError, OSError) as e:
            return FlextResult(success=False, error=f"Session creation failed: {e}")

    def validate_session(self, session: FlextSession) -> FlextResult[bool]:
        """Validate a session.

        Args:
            session: Session to validate

        Returns:
            FlextResult indicating if session is valid

        """
        try:
            if not session.is_valid():
                return FlextResult(success=False, error="Session is not valid")

            return FlextResult.ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult(success=False, error=f"Session validation failed: {e}")

    def revoke_session(self, session: FlextSession) -> FlextResult[bool]:
        """Revoke a session.

        Args:
            session: Session to revoke

        Returns:
            FlextResult indicating success

        """
        try:
            session.revoke()
            return FlextResult.ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult(success=False, error=f"Session revocation failed: {e}")


class FlextAuthorizationService(FlextDomainService):
    """Service for authorization operations."""

    def execute(self) -> FlextResult[str]:
        """Execute service operation (required by FlextDomainService).

        This method is required by the abstract base class but services
        provide specific methods for their operations.

        Returns:
            FlextResult indicating this method should not be used directly

        """
        return FlextResult.fail(
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
                return FlextResult.ok(True)

            # If roles are provided, check role permissions
            if roles:
                user_role = roles.get(user.role.value)
                if user_role and user_role.has_permission(resource, action):
                    return FlextResult.ok(True)

            return FlextResult(success=True, data=False)

        except (KeyError, ValueError, TypeError, AttributeError) as e:
            return FlextResult(success=False, error=f"Permission check failed: {e}")

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
                return FlextResult(success=False, error="Role name is required")

            role = FlextRole(
                id=str(uuid.uuid4()),
                name=name,
                description=description,
                permissions=permissions or [],
            )

            if not role.is_valid():
                return FlextResult(success=False, error="Invalid role data")

            return FlextResult(success=True, data=role)

        except (ValueError, TypeError, AttributeError, KeyError) as e:
            return FlextResult(success=False, error=f"Role creation failed: {e}")


# Backwards compatibility aliases
AuthenticationService = FlextAuthenticationService
SessionService = FlextSessionService
AuthorizationService = FlextAuthorizationService
