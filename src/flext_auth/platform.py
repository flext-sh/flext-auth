"""FLEXT Auth Platform - Unified authentication and authorization platform.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

Platform class providing unified access to authentication and authorization services.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextContainer, FlextError, FlextResult

from flext_auth.application.services import (
    FlextAuthenticationService,
    FlextAuthorizationService,
    FlextSessionService,
)

if TYPE_CHECKING:
    from flext_auth.domain.entities import (
        FlextPermission,
        FlextRole,
        FlextSession,
        FlextUser,
    )


class FlextAuthPlatform:
    """Platform for authentication and authorization operations."""

    def __init__(self, config: dict[str, object] | None = None) -> None:
        """Initialize auth platform.

        Args:
            config: Platform configuration

        """
        self.config = config or {}
        self.container = FlextContainer()
        self._setup_services()

    def _setup_services(self) -> None:
        """Create and register platform services."""
        # Register services in container
        self.container.register(
            "auth_service",
            FlextAuthenticationService(),
        )
        self.container.register("session_service", FlextSessionService())
        self.container.register(
            "authz_service",
            FlextAuthorizationService(),
        )

    @property
    def auth_service(self) -> FlextAuthenticationService:
        """Get authentication service."""
        result = self.container.get("auth_service")
        if result.is_success:
            service = result.data
            if not isinstance(service, FlextAuthenticationService):
                msg = f"Invalid auth service type: expected FlextAuthenticationService, got {type(service).__name__}"
                raise FlextError(msg)
            return service
        msg = f"Authentication service not available: {result.error}"
        raise FlextError(msg)

    @property
    def session_service(self) -> FlextSessionService:
        """Get session service using FLEXT service resolution."""
        result = self.container.get("session_service")
        if result.is_success:
            service = result.data
            if not isinstance(service, FlextSessionService):
                msg = f"Invalid session service type: expected FlextSessionService, got {type(service).__name__}"
                raise FlextError(msg)
            return service
        msg = f"Failed to get session service: {result.error}"
        raise FlextError(msg)

    @property
    def authz_service(self) -> FlextAuthorizationService:
        """Get authorization service using FLEXT service resolution."""
        result = self.container.get("authz_service")
        if result.is_success:
            service = result.data
            if not isinstance(service, FlextAuthorizationService):
                msg = f"Invalid authorization service type: expected FlextAuthorizationService, got {type(service).__name__}"
                raise FlextError(msg)
            return service
        msg = f"Failed to get authorization service: {result.error}"
        raise FlextError(msg)

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
            users: Dictionary of users

        Returns:
            FlextResult containing authenticated user

        """
        return self.auth_service.authenticate_user(username, password, users)

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
        return self.auth_service.create_user(username, email, password)

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
        return self.session_service.create_session(
            user,
            expires_minutes,
            ip_address,
            user_agent,
        )

    def validate_session(self, session: FlextSession) -> FlextResult[bool]:
        """Validate a session.

        Args:
            session: Session to validate

        Returns:
            FlextResult indicating if session is valid

        """
        return self.session_service.validate_session(session)

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
        return self.authz_service.check_permission(user, resource, action, roles)

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
        return self.authz_service.create_role(name, description, permissions)

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
        return self.auth_service.change_password(user, old_password, new_password)

    def get_authenticator(self) -> FlextAuthenticationService:
        """Get the authenticator service (alias for auth_service).

        Returns:
            Authentication service

        """
        return self.auth_service


# Backwards compatibility alias
AuthPlatform = FlextAuthPlatform
